"""Focused tests for the experimental A/B comparison harness's own
isolation and trace-parsing logic -- NOT an end-to-end/live-LLM test suite
(see `concern_tree_harness.py --mock` for a manual plumbing self-check)."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest import mock

from utilities.autopatcher.tools.concern_tree_harness import (
    strip_to_experimental_input,
    parse_challenger_prompt_trace,
    extract_archived_concerns,
    run_comparison,
    run_tree_only,
    _load_inputs,
    _ReplayLLM,
    _V2_ONLY_KEYS,
    main,
)


# Generic, non-urllib3 synthetic fixtures representing one archived real
# Challenger call: a prompt trace (system prompt + the three ## sections
# challenge_patch() actually sends) and the raw response that call
# produced.
_SYNTHETIC_PROMPT_TRACE = (
    "# Patch Challenger Prompt\n\nSome system prompt text goes here.\n\n"
    "## Repository evidence (selected by static analysis)\n\n"
    "if flag: raise Err()\nop()\n\n"
    "## Vulnerability report\n\n"
    "A generic advisory describing an unsafe operation under some condition.\n\n"
    "## Proposed patch\n\n"
    "--- a/mod.py\n+++ b/mod.py\n@@\n+if flag: raise Err()\n"
)

_SYNTHETIC_ARCHIVED_RESPONSE = (
    "Verification status: VERIFIED_FIXED\n\n"
    "Concerns:\n\n"
    "1. Role: primary\n"
    "   Description: whether the unsafe operation still runs under default execution\n"
    "   Default execution reachability: blocked\n"
    "   Reachability provenance: if flag: raise Err()\n"
    "   Requires explicit non-default action: false\n"
    "   Contract addresses override: not_applicable\n\n"
    "Edge cases:\n- none\n\nPotential issues:\n- none\n\nSummary:\n- none\n"
)


# A generic, non-urllib3 archived response exercising every skip reason
# `extract_archived_concerns` must surface: concern 1 is cleanly valid;
# "1" repeats (duplicate concern number); concern 2 has an invalid Role;
# concern 3 has no Description line at all; concern 4 is cleanly valid
# again (proves one bad block never corrupts its neighbors).
_SYNTHETIC_RESPONSE_MALFORMED_CONCERNS = (
    "Verification status: INSUFFICIENT_EVIDENCE\n\n"
    "Concerns:\n\n"
    "1. Role: primary\n"
    "   Description: first valid concern description\n\n"
    "1. Role: additional\n"
    "   Description: a duplicate concern number\n\n"
    "2. Role: bogus_role\n"
    "   Description: a concern with an invalid role\n\n"
    "3. Role: additional\n"
    "   Something else: filler, no Description field at all\n\n"
    "4. Role: additional\n"
    "   Description: second valid concern description\n\n"
    "Edge cases:\n- none\n\nPotential issues:\n- none\n\nSummary:\n- none\n"
)

_RESPONSE_WITHOUT_CONCERNS_SECTION = (
    "Verification status: VERIFIED_FIXED\n\n"
    "Edge cases:\n- none\n\nPotential issues:\n- none\n\nSummary:\n- none\n"
)

_STUB_TREE_RESULT = {
    "root_id": "n0", "root_proposition": "stub", "root_final_status": "UNRESOLVED",
    "nodes": {}, "totals": {
        "total_nodes": 1, "max_depth_reached": 0, "semantic_evaluation_calls": 1,
        "evidence_requests": 0, "evidence_acquired": 0, "invalid_provenance_count": 0, "unresolved_count": 1,
    },
}


class _RaisingIfCalledLLM:
    """A baseline LLM stand-in that fails the test immediately if it is
    ever invoked -- used to prove a code path performs NO baseline
    sampling at all (a stronger check than merely inspecting the
    resulting JSON)."""

    def complete(self, system_prompt, user_message, stage="unknown"):
        raise AssertionError("baseline arm made an LLM call in paired-replay mode")


class _RecordingLLM:
    """A tree LLM stand-in that records every prompt it was given and
    always returns a valid terminal UNRESOLVED action, so the tree
    resolves in one step without needing scripted responses."""

    def __init__(self):
        self.calls = []

    def complete(self, system_prompt, user_message, stage=None, **_kwargs):
        self.calls.append((system_prompt, user_message, stage))
        return "Action: UNRESOLVED\nReason: recorded, no real evaluation\n"


class TestExperimentalInputIsolation:
    def test_only_role_and_proposition_survive(self):
        concern = {
            "concern_role": "primary",
            "description": "the operation can occur",
            "default_execution_reachability": "blocked",
            "preceding_guard": "present",
            "guard_default_state": "condition_true_under_default",
            "guard_effect": "prevents_operation",
            "reentry_state_propagation": "not_applicable",
            "requires_explicit_non_default_action": "false",
            "contract_addresses_override": "not_applicable",
            "consequence": "NON_BLOCKING",
            "reachability_facts": {"preceding_guard": "present"},
            "malformed": False,
            "malformed_reason": None,
        }
        result = strip_to_experimental_input(concern)
        assert result == {"concern_role": "primary", "proposition": "the operation can occur"}

    def test_every_v2_only_key_is_absent_from_output(self):
        concern = {"concern_role": "additional", "description": "d"}
        for key in _V2_ONLY_KEYS:
            concern[key] = "some v2 value"
        result = strip_to_experimental_input(concern)
        assert not (_V2_ONLY_KEYS & set(result.keys()))
        assert set(result.keys()) == {"concern_role", "proposition"}

    def test_missing_description_is_empty_proposition_not_a_crash(self):
        result = strip_to_experimental_input({"concern_role": "primary"})
        assert result["proposition"] == ""


class TestChallengerPromptTraceParsing:
    def test_full_trace_with_all_three_sections(self):
        text = (
            "## Repository evidence (selected by static analysis)\n\n"
            "def f():\n    pass\n\n"
            "## Vulnerability report\n\n"
            "Some advisory text.\n\n"
            "## Proposed patch\n\n"
            "--- a/f.py\n+++ b/f.py\n"
        )
        sections = parse_challenger_prompt_trace(text)
        assert sections["code_context"] == "def f():\n    pass"
        assert sections["vulnerability_text"] == "Some advisory text."
        assert sections["patch"].startswith("--- a/f.py")

    def test_trace_without_repository_evidence_section(self):
        text = (
            "## Vulnerability report\n\nSome advisory text.\n\n"
            "## Proposed patch\n\n--- a/f.py\n"
        )
        sections = parse_challenger_prompt_trace(text)
        assert sections["code_context"] == ""
        assert sections["vulnerability_text"] == "Some advisory text."


class TestReplayStub:
    """`_ReplayLLM` itself -- items 2, 4, 5 of the required test list."""

    def test_returns_archived_response_exactly(self):
        replay = _ReplayLLM(_SYNTHETIC_ARCHIVED_RESPONSE)
        assert replay.complete("system", "user", stage="challenger") == _SYNTHETIC_ARCHIVED_RESPONSE

    def test_makes_no_network_or_provider_call(self):
        """Proven by construction, not merely by absence of an exception:
        patching the real LLMClient to explode on construction, then
        exercising a full baseline `challenge_patch()` call through
        `_ReplayLLM`, must never trigger it."""
        with mock.patch(
            "utilities.autopatcher.llm_client.LLMClient",
            side_effect=AssertionError("a real LLMClient must never be constructed for replay"),
        ):
            from utilities.autopatcher.patch_challenger import challenge_patch
            replay = _ReplayLLM(_SYNTHETIC_ARCHIVED_RESPONSE)
            result = challenge_patch(
                "A generic advisory.", "--- a/mod.py\n", replay, code_context="if flag: raise Err()\nop()",
            )
            assert result["schema_version"] == "concerns_v1"

    def test_second_call_raises(self):
        replay = _ReplayLLM(_SYNTHETIC_ARCHIVED_RESPONSE)
        replay.complete("system", "user")
        try:
            replay.complete("system", "user")
            assert False, "expected RuntimeError on second call"
        except RuntimeError as exc:
            assert "more than once" in str(exc)


class TestLoadInputsFailsClosed:
    """Item 6: prompt-without-response fails closed."""

    def test_prompt_without_response_raises(self, tmp_path):
        prompt_file = tmp_path / "006_challenger.prompt.txt"
        prompt_file.write_text(_SYNTHETIC_PROMPT_TRACE)
        args = SimpleNamespace(
            mock=False, challenger_prompt_file=str(prompt_file), challenger_response_file=None,
            vulnerability_text_file=None, code_context_file=None, patch_file=None,
        )
        try:
            _load_inputs(args)
            assert False, "expected SystemExit"
        except SystemExit as exc:
            assert "requires --challenger-response-file" in str(exc)

    def test_prompt_with_response_succeeds_and_is_archived_source(self, tmp_path):
        prompt_file = tmp_path / "006_challenger.prompt.txt"
        response_file = tmp_path / "006_challenger.response.txt"
        prompt_file.write_text(_SYNTHETIC_PROMPT_TRACE)
        response_file.write_text(_SYNTHETIC_ARCHIVED_RESPONSE)
        args = SimpleNamespace(
            mock=False, challenger_prompt_file=str(prompt_file), challenger_response_file=str(response_file),
            vulnerability_text_file=None, code_context_file=None, patch_file=None,
        )
        loaded = _load_inputs(args)
        assert loaded.baseline_source == "archived_challenger_response"
        assert loaded.archived_response == _SYNTHETIC_ARCHIVED_RESPONSE
        assert loaded.code_context == "if flag: raise Err()\nop()"

    def test_generic_explicit_mode_is_labeled_live_not_replay(self, tmp_path, capsys):
        vuln_file = tmp_path / "vuln.txt"
        patch_file = tmp_path / "patch.diff"
        vuln_file.write_text("A generic advisory.")
        patch_file.write_text("--- a/mod.py\n")
        args = SimpleNamespace(
            mock=False, challenger_prompt_file=None, challenger_response_file=None,
            vulnerability_text_file=str(vuln_file), code_context_file=None, patch_file=str(patch_file),
        )
        loaded = _load_inputs(args)
        assert loaded.baseline_source == "live_llm_call_generic_mode"
        assert loaded.archived_response is None
        assert "NOT paired replay" in capsys.readouterr().err


class TestPairedReplayComparison:
    """Items 1, 3, 7, 8, 9, 10, 11 -- the core paired-replay guarantee,
    exercised through `run_comparison()` directly (no CLI/network
    plumbing) using the SAME synthetic archived pair throughout."""

    def _run(self):
        sections = parse_challenger_prompt_trace(_SYNTHETIC_PROMPT_TRACE)
        baseline_llm = _ReplayLLM(_SYNTHETIC_ARCHIVED_RESPONSE)
        tree_llm = _RecordingLLM()
        result = run_comparison(
            sections["vulnerability_text"], sections["code_context"], sections["patch"],
            baseline_llm=baseline_llm, tree_llm=tree_llm, baseline_source="archived_challenger_response",
            challenger_prompt_file="p.txt", challenger_response_file="r.txt",
        )
        return result, baseline_llm, tree_llm

    def test_baseline_result_is_the_parsed_archived_response(self):
        """Item 1 + 3: the replay stub is what's called, and the baseline
        result is exactly what production parsing derives from it. The
        fixture is a legacy concerns_v1 response asserting `blocked`, which
        production fails closed to `unresolved` (a single unscoped quote)."""
        result, baseline_llm, _tree_llm = self._run()
        assert baseline_llm._called is True
        assert result["baseline_verification_status"] == "INSUFFICIENT_EVIDENCE"
        assert result["concern_count"] == 1
        concern = result["concerns"][0]
        assert concern["baseline"]["default_execution_reachability"] == "unresolved"
        assert concern["baseline"]["consequence"] == "UNRESOLVED"

    def test_tree_receives_only_proposition_and_repo_evidence(self):
        """Item 7: inspect the ACTUAL prompts the tree LLM received."""
        _result, _baseline_llm, tree_llm = self._run()
        assert len(tree_llm.calls) == 1
        _system, user_message, stage = tree_llm.calls[0]
        assert stage == "concern_tree_evaluator"
        assert "whether the unsafe operation still runs under default execution" in user_message
        assert "if flag: raise Err()" in user_message  # repository evidence
        assert "op()" in user_message

    def test_no_v2_fields_leak_into_tree_prompt(self):
        """Item 8, checked at the actual prompt-text level, not just the
        intermediate dict."""
        _result, _baseline_llm, tree_llm = self._run()
        _system, user_message, _stage = tree_llm.calls[0]
        for v2_term in (
            "preceding_guard", "guard_default_state", "guard_effect",
            "reentry_state_propagation", "NON_BLOCKING", "concerns_v1",
        ):
            assert v2_term not in user_message

    def test_archived_response_text_never_reaches_tree(self):
        """Item 9: the raw archived response's own distinguishing text
        (the free-form Verification-status/Edge-cases scaffolding, never
        part of a clean proposition) must not appear in what the tree saw."""
        _result, _baseline_llm, tree_llm = self._run()
        _system, user_message, _stage = tree_llm.calls[0]
        assert "Verification status: VERIFIED_FIXED" not in user_message
        assert "Edge cases:" not in user_message

    def test_vulnerability_text_never_reaches_tree(self):
        """Item 10."""
        _result, _baseline_llm, tree_llm = self._run()
        _system, user_message, _stage = tree_llm.calls[0]
        assert "A generic advisory describing an unsafe operation" not in user_message

    def test_artifact_records_archived_provenance(self):
        """Item 11."""
        result, _baseline_llm, _tree_llm = self._run()
        assert result["baseline_source"] == "archived_challenger_response"
        assert result["challenger_prompt_file"] == "p.txt"
        assert result["challenger_response_file"] == "r.txt"
        # And the raw response text is never embedded in the artifact.
        assert _SYNTHETIC_ARCHIVED_RESPONSE not in json.dumps(result)


class TestMainStillWorksEndToEnd:
    """Item 12: --mock mode unaffected by the fix."""

    def test_mock_mode(self, tmp_path):
        output = tmp_path / "mock.json"
        rc = main(["--mock", "--output", str(output)])
        assert rc == 0
        result = json.loads(output.read_text())
        assert result["baseline_source"] == "mock"
        assert result["concern_count"] == 1

    def test_main_paired_replay_uses_replay_stub_never_llmclient_for_baseline(self, tmp_path):
        """End-to-end through `main()`'s own CLI wiring: the baseline arm
        must never touch a real `LLMClient`, and the (mocked) tree arm's
        LLMClient is called exactly once per discovered concern -- never
        for baseline."""
        prompt_file = tmp_path / "006_challenger.prompt.txt"
        response_file = tmp_path / "006_challenger.response.txt"
        prompt_file.write_text(_SYNTHETIC_PROMPT_TRACE)
        response_file.write_text(_SYNTHETIC_ARCHIVED_RESPONSE)
        output = tmp_path / "comparison.json"

        fake_client = mock.MagicMock()
        fake_client.complete.return_value = "Action: UNRESOLVED\nReason: mocked tree call\n"

        with mock.patch("utilities.autopatcher.llm_client.LLMClient", return_value=fake_client) as client_cls:
            rc = main([
                "--challenger-prompt-file", str(prompt_file),
                "--challenger-response-file", str(response_file),
                "--output", str(output),
            ])
        assert rc == 0
        assert client_cls.call_count == 1  # constructed once, for the TREE arm only
        assert fake_client.complete.call_count == 1  # one tree evaluation, zero baseline calls

        result = json.loads(output.read_text())
        assert result["baseline_source"] == "archived_challenger_response"
        assert result["concerns"][0]["baseline"]["default_execution_reachability"] == "unresolved"


class TestExtractArchivedConcerns:
    """Items 1-6: the minimal, fail-closed Role+Description extractor."""

    def test_clean_extraction(self):
        concerns, skipped = extract_archived_concerns(_SYNTHETIC_ARCHIVED_RESPONSE)
        assert skipped == []
        assert concerns == [{
            "concern_number": 1, "concern_role": "primary",
            "description": "whether the unsafe operation still runs under default execution",
        }]

    def test_duplicate_concern_number_surfaced(self):
        concerns, skipped = extract_archived_concerns(_SYNTHETIC_RESPONSE_MALFORMED_CONCERNS)
        dup = [s for s in skipped if s["concern_number"] == 1]
        assert dup == [{"concern_number": 1, "reason": "duplicate_concern_number"}]

    def test_invalid_role_surfaced(self):
        _concerns, skipped = extract_archived_concerns(_SYNTHETIC_RESPONSE_MALFORMED_CONCERNS)
        assert {"concern_number": 2, "reason": "invalid_or_missing_role"} in skipped

    def test_missing_description_surfaced(self):
        _concerns, skipped = extract_archived_concerns(_SYNTHETIC_RESPONSE_MALFORMED_CONCERNS)
        assert {"concern_number": 3, "reason": "missing_description"} in skipped

    def test_one_bad_block_never_corrupts_neighbors(self):
        """Concern 4, after three consecutive bad blocks (including
        concern 1's own number being ambiguous), still extracts cleanly
        -- fail-closed is per-concern, never per-response."""
        concerns, _skipped = extract_archived_concerns(_SYNTHETIC_RESPONSE_MALFORMED_CONCERNS)
        numbers = {c["concern_number"] for c in concerns}
        assert numbers == {4}

    def test_missing_concerns_section_fails_closed_visibly(self):
        concerns, skipped = extract_archived_concerns(_RESPONSE_WITHOUT_CONCERNS_SECTION)
        assert concerns == []
        assert skipped == [{"concern_number": None, "reason": "no_concerns_section"}]

    def test_never_invokes_full_semantic_parser_or_challenge_patch(self):
        """Item 6, proven structurally: patch the full v2 dispatcher AND
        challenge_patch itself to explode if called, then extract from a
        response shaped exactly like a real archived urllib3 concern
        block -- extraction must still succeed cleanly, proving it never
        goes anywhere near that code path, regardless of how the full
        parser would handle this exact shape (which is irrelevant to the
        invariant this test protects: archival extraction's independence
        from production semantic parsing)."""
        response_matching_real_archived_concern_shape = (
            "Verification status: VERIFIED_FIXED\n\n"
            "Concerns:\n\n"
            "1. Role: primary\n"
            "   Description: whether the unsafe operation still runs under default execution\n"
            "   Operation present in evidence: present\n"
            "   Preceding guard: present\n"
            "   Guard provenance: if flag: raise Err()\n"
            "   Operation provenance: op()\n"
            "   Guard default state: condition_true_under_default\n"
            "   Guard default state provenance: flag: bool = True\n"
            "   Guard effect: neutralizes_operation\n"
            "   Guard effect provenance: data.pop(key, None)\n"
            "   Reentry state propagation: not_applicable\n"
            "   Requires explicit non-default action: not_applicable\n\n"
            "Edge cases:\n- none\n\nPotential issues:\n- none\n\nSummary:\n- none\n"
        )
        with mock.patch(
            "utilities.autopatcher.patch_challenger._parse_concerns",
            side_effect=AssertionError("full v2 semantic parser must not be invoked by the archival extractor"),
        ), mock.patch(
            "utilities.autopatcher.patch_challenger.challenge_patch",
            side_effect=AssertionError("challenge_patch must not be invoked by the archival extractor"),
        ):
            concerns, skipped = extract_archived_concerns(response_matching_real_archived_concern_shape)
        assert skipped == []
        assert concerns[0]["concern_role"] == "primary"
        assert concerns[0]["description"] == "whether the unsafe operation still runs under default execution"


class TestTreeOnlyCLI:
    """Item 7: --tree-only requires archived prompt + response."""

    def test_tree_only_without_prompt_file_fails_closed(self, tmp_path):
        output = tmp_path / "out.json"
        try:
            main(["--tree-only", "--mock", "--output", str(output)])
            assert False, "expected SystemExit"
        except SystemExit as exc:
            assert "--tree-only requires --challenger-prompt-file" in str(exc)
        assert not output.exists()

    def test_tree_only_with_prompt_but_no_response_fails_closed(self, tmp_path):
        prompt_file = tmp_path / "p.txt"
        prompt_file.write_text(_SYNTHETIC_PROMPT_TRACE)
        output = tmp_path / "out.json"
        try:
            main(["--tree-only", "--challenger-prompt-file", str(prompt_file), "--output", str(output)])
            assert False, "expected SystemExit"
        except SystemExit as exc:
            assert "requires --challenger-response-file" in str(exc)
        assert not output.exists()


class TestTreeOnlyRun:
    """Items 8-16: the core tree-only data flow, exercised through
    `run_tree_only()` directly (no CLI/network plumbing) and through
    `main()` where the CLI wiring itself is what's being proven."""

    def _sections(self):
        return parse_challenger_prompt_trace(_SYNTHETIC_PROMPT_TRACE)

    def test_one_tree_evaluation_per_valid_concern(self):
        """Item 9. Also exercises skipped_concerns flowing through
        end to end (item 16)."""
        sections = self._sections()
        concerns, skipped = extract_archived_concerns(_SYNTHETIC_RESPONSE_MALFORMED_CONCERNS)
        tree_llm = _RecordingLLM()
        result = run_tree_only(
            sections["code_context"], sections["patch"], tree_llm, concerns,
            skipped_concerns=skipped,
        )
        # Only concern 4 extracts cleanly: concern 1's own number is
        # ambiguous (duplicated), concern 2 has an invalid Role, concern 3
        # has no Description at all.
        assert len(tree_llm.calls) == len(concerns) == 1
        assert result["archived_concern_count"] == 1
        assert [c["reason"] for c in result["skipped_concerns"]] == [
            "duplicate_concern_number", "invalid_or_missing_role", "missing_description",
        ]

    def test_tree_receives_only_description_as_proposition(self):
        """Item 10."""
        sections = self._sections()
        concerns, _skipped = extract_archived_concerns(_SYNTHETIC_ARCHIVED_RESPONSE)
        tree_llm = _RecordingLLM()
        run_tree_only(sections["code_context"], sections["patch"], tree_llm, concerns)
        assert len(tree_llm.calls) == 1
        _system, user_message, stage = tree_llm.calls[0]
        assert stage == "concern_tree_evaluator"
        assert "whether the unsafe operation still runs under default execution" in user_message
        assert "if flag: raise Err()" in user_message  # repository evidence, still present

    def test_vulnerability_text_never_reaches_tree(self):
        """Item 11."""
        sections = self._sections()
        concerns, _skipped = extract_archived_concerns(_SYNTHETIC_ARCHIVED_RESPONSE)
        tree_llm = _RecordingLLM()
        run_tree_only(sections["code_context"], sections["patch"], tree_llm, concerns)
        _system, user_message, _stage = tree_llm.calls[0]
        assert "A generic advisory describing an unsafe operation" not in user_message

    def test_raw_archived_response_never_reaches_tree(self):
        """Item 12."""
        sections = self._sections()
        concerns, _skipped = extract_archived_concerns(_SYNTHETIC_ARCHIVED_RESPONSE)
        tree_llm = _RecordingLLM()
        run_tree_only(sections["code_context"], sections["patch"], tree_llm, concerns)
        _system, user_message, _stage = tree_llm.calls[0]
        assert "Verification status: VERIFIED_FIXED" not in user_message
        assert "Edge cases:" not in user_message
        assert "Requires explicit non-default action" not in user_message

    def test_v2_semantic_fields_never_reach_tree(self):
        """Item 13."""
        sections = self._sections()
        concerns, _skipped = extract_archived_concerns(_SYNTHETIC_ARCHIVED_RESPONSE)
        tree_llm = _RecordingLLM()
        run_tree_only(sections["code_context"], sections["patch"], tree_llm, concerns)
        _system, user_message, _stage = tree_llm.calls[0]
        for v2_term in (
            "preceding_guard", "guard_default_state", "guard_effect",
            "reentry_state_propagation", "NON_BLOCKING", "concerns_v1",
        ):
            assert v2_term not in user_message

    def test_output_has_mode_tree_only_and_no_baseline_key(self):
        """Items 14, 15 -- checked recursively, everywhere in the artifact."""
        sections = self._sections()
        concerns, skipped = extract_archived_concerns(_SYNTHETIC_ARCHIVED_RESPONSE)
        tree_llm = _RecordingLLM()
        result = run_tree_only(
            sections["code_context"], sections["patch"], tree_llm, concerns, skipped_concerns=skipped,
        )
        assert result["mode"] == "tree_only"

        def _assert_no_baseline_key(obj):
            if isinstance(obj, dict):
                assert "baseline" not in obj, f"unexpected 'baseline' key found in {obj.keys()}"
                for v in obj.values():
                    _assert_no_baseline_key(v)
            elif isinstance(obj, list):
                for v in obj:
                    _assert_no_baseline_key(v)

        _assert_no_baseline_key(result)

    def test_raw_response_not_embedded_in_artifact(self):
        sections = self._sections()
        concerns, _skipped = extract_archived_concerns(_SYNTHETIC_ARCHIVED_RESPONSE)
        tree_llm = _RecordingLLM()
        result = run_tree_only(sections["code_context"], sections["patch"], tree_llm, concerns)
        assert _SYNTHETIC_ARCHIVED_RESPONSE not in json.dumps(result)

    def test_main_tree_only_makes_zero_challenger_baseline_calls(self, tmp_path):
        """Item 8, proven structurally at the CLI level: patch the
        harness's own imported `challenge_patch` name to explode if
        called at all."""
        prompt_file = tmp_path / "p.txt"
        response_file = tmp_path / "r.txt"
        prompt_file.write_text(_SYNTHETIC_PROMPT_TRACE)
        response_file.write_text(_SYNTHETIC_ARCHIVED_RESPONSE)
        output = tmp_path / "out.json"
        with mock.patch(
            "utilities.autopatcher.tools.concern_tree_harness.challenge_patch",
            side_effect=AssertionError("challenge_patch must never be called in --tree-only mode"),
        ), mock.patch(
            "utilities.autopatcher.tools.concern_tree_harness._ReplayLLM",
            side_effect=AssertionError("_ReplayLLM must never be constructed in --tree-only mode"),
        ):
            rc = main([
                "--challenger-prompt-file", str(prompt_file),
                "--challenger-response-file", str(response_file),
                "--output", str(output), "--tree-only", "--mock",
            ])
        assert rc == 0
        result = json.loads(output.read_text())
        assert result["mode"] == "tree_only"
        assert result["archived_concern_count"] == 1


class TestInvestigationContextWiring:
    """Items 17-20: real evidence-acquisition wiring."""

    def test_constructed_once_and_reused_across_concerns(self, tmp_path):
        """Items 17, 18 -- proven by mocking the production constructor
        itself (call-count assertion) and confirming the SAME object
        identity reaches every concern's Tree evaluation."""
        prompt_file = tmp_path / "p.txt"
        response_file = tmp_path / "r.txt"
        prompt_file.write_text(_SYNTHETIC_PROMPT_TRACE)
        two_concern_response = (
            "Verification status: VERIFIED_FIXED\n\nConcerns:\n\n"
            "1. Role: primary\n   Description: first concern description\n\n"
            "2. Role: additional\n   Description: second concern description\n\n"
            "Edge cases:\n- none\n\nPotential issues:\n- none\n\nSummary:\n- none\n"
        )
        response_file.write_text(two_concern_response)
        output = tmp_path / "out.json"

        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        (repo_dir / "mod.py").write_text("def f():\n    pass\n")

        sentinel_ctx = object()
        with mock.patch(
            "utilities.autopatcher.candidate_enrichment.build_investigation_context",
            return_value=sentinel_ctx,
        ) as build_ctx, mock.patch(
            "utilities.autopatcher.tools.concern_tree_harness.evaluate_concern_tree",
            return_value=_STUB_TREE_RESULT,
        ) as eval_tree:
            rc = main([
                "--challenger-prompt-file", str(prompt_file),
                "--challenger-response-file", str(response_file),
                "--repo-root", str(repo_dir),
                "--output", str(output),
                "--tree-only", "--mock",
            ])
        assert rc == 0
        assert build_ctx.call_count == 1  # constructed exactly once for the whole run
        assert eval_tree.call_count == 2  # one call per concern
        for call in eval_tree.call_args_list:
            assert call.kwargs["investigation_context"] is sentinel_ctx  # SAME object, every time

    def test_investigation_context_not_built_without_repo_root(self, tmp_path):
        """`main()` never even attempts to construct an investigation
        context when `--repo-root` is absent -- the production
        `build_investigation_context` must not be called at all."""
        prompt_file = tmp_path / "p.txt"
        response_file = tmp_path / "r.txt"
        prompt_file.write_text(_SYNTHETIC_PROMPT_TRACE)
        response_file.write_text(_SYNTHETIC_ARCHIVED_RESPONSE)
        output = tmp_path / "out.json"

        with mock.patch(
            "utilities.autopatcher.candidate_enrichment.build_investigation_context",
        ) as build_ctx:
            rc = main([
                "--challenger-prompt-file", str(prompt_file),
                "--challenger-response-file", str(response_file),
                "--output", str(output), "--tree-only", "--mock",
            ])
        assert rc == 0
        assert build_ctx.call_count == 0

    def test_request_evidence_succeeds_with_real_repo_and_context(self, tmp_path):
        """Item 19 -- a real, tiny, generic (non-urllib3) fixture repo and
        a real `build_investigation_context()` call (not mocked)."""
        prompt_file = tmp_path / "p.txt"
        response_file = tmp_path / "r.txt"
        prompt_file.write_text(_SYNTHETIC_PROMPT_TRACE)
        response_file.write_text(_SYNTHETIC_ARCHIVED_RESPONSE)
        output = tmp_path / "out.json"

        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        (repo_dir / "mod.py").write_text("def widget():\n    if flag:\n        raise Err()\n    op()\n")

        class _AcquiringLLM:
            def __init__(self):
                self.n = 0

            def complete(self, system_prompt, user_message, stage=None, **_kwargs):
                self.n += 1
                if self.n == 1:
                    return (
                        "Action: REQUEST_EVIDENCE\nRationale: need to see the function\n"
                        "Request type: symbol_definition\nFile hint: mod.py\nSymbol: widget\n"
                    )
                return (
                    "Necessary conditions:\n- nothing further beyond the cited fact\n"
                    "Evidence conflict check:\n- none found\n"
                    "Action: PROVEN\nRationale: guard raises before op\nCitations:\n- raise Err()\n"
                )

        fake_client = _AcquiringLLM()
        with mock.patch("utilities.autopatcher.llm_client.LLMClient", return_value=fake_client):
            rc = main([
                "--challenger-prompt-file", str(prompt_file),
                "--challenger-response-file", str(response_file),
                "--repo-root", str(repo_dir),
                "--output", str(output),
                "--tree-only",
            ])
        assert rc == 0
        result = json.loads(output.read_text())
        concern = result["concerns"][0]
        assert concern["tree"]["metrics"]["evidence_requests"] == 1
        assert concern["tree"]["metrics"]["evidence_acquired"] == 1
        assert concern["tree"]["root_final_status"] == "PROVEN"

    def test_acquisition_fails_closed_when_unresolvable(self, tmp_path):
        """Item 20 -- a real repo/context, but the requested file does
        not exist in it."""
        prompt_file = tmp_path / "p.txt"
        response_file = tmp_path / "r.txt"
        prompt_file.write_text(_SYNTHETIC_PROMPT_TRACE)
        response_file.write_text(_SYNTHETIC_ARCHIVED_RESPONSE)
        output = tmp_path / "out.json"

        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        (repo_dir / "mod.py").write_text("def widget():\n    pass\n")

        class _UnresolvableRequestLLM:
            def complete(self, system_prompt, user_message, stage=None, **_kwargs):
                return (
                    "Action: REQUEST_EVIDENCE\nRationale: need a file that does not exist\n"
                    "Request type: file_source\nFile hint: does_not_exist.py\nSymbol: none\n"
                )

        fake_client = _UnresolvableRequestLLM()
        with mock.patch("utilities.autopatcher.llm_client.LLMClient", return_value=fake_client):
            rc = main([
                "--challenger-prompt-file", str(prompt_file),
                "--challenger-response-file", str(response_file),
                "--repo-root", str(repo_dir),
                "--output", str(output),
                "--tree-only",
            ])
        assert rc == 0
        result = json.loads(output.read_text())
        concern = result["concerns"][0]
        assert concern["tree"]["root_final_status"] == "UNRESOLVED"
        assert concern["tree"]["metrics"]["evidence_acquired"] == 0
