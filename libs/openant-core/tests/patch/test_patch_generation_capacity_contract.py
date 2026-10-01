"""Tests for the Patch Generation combined-request technical-capacity
contract (utilities.autopatcher.patch_generator.compute_patch_generation_
capacity / fit_patch_generation_context).

Context: the Patch Generation audit found that individual context sections
(_repo_code, _repository_understanding_ctx, _plan_ctx, _planner_evidence_ctx,
_strategy_ctx, _slice_ctx, ...) were each bounded against THEIR OWN producing
stage's technical capacity, never against the actual combined request
generate_patch_raw() sends: system prompt (patch_generator.md) +
"## Vulnerability report" + vulnerability_text + "## Repository code
context" + code_context + (optionally) "## Retry instruction" + retry_hint.
These tests prove the new shared contract closes that gap: one capacity
calculation that accounts for every fixed string the real request contains,
and one whole-block-or-omit fitting function that guarantees the combined
`code_context` it produces, plus that overhead, never exceeds it -- and
that a REQUIRED block (the Final-Target Remediation Slice, or its Post-
Patch Recovery replacement) is never silently dropped to make the rest fit.
"""

from __future__ import annotations

from utilities.autopatcher.patch_generator import (
    _PROMPT_PATH,
    _VULN_HEADER,
    _CODE_CONTEXT_HEADER,
    _RETRY_HEADER,
    PATCH_GENERATION_REQUIRED_LABEL,
    compute_patch_generation_capacity,
    fit_patch_generation_context,
    generate_patch_raw,
)


class TestComputePatchGenerationCapacity:
    def test_system_prompt_and_vulnerability_text_are_counted(self):
        vuln = "x" * 10_000
        cap_empty = compute_patch_generation_capacity("")
        cap_with_vuln = compute_patch_generation_capacity(vuln)
        # A longer vulnerability_text must shrink the remaining ceiling by
        # (at least) its own length -- if it weren't counted, both calls
        # would report the same ceiling.
        assert cap_with_vuln.source_capacity_chars < cap_empty.source_capacity_chars
        assert (
            cap_empty.source_capacity_chars - cap_with_vuln.source_capacity_chars
            >= len(vuln)
        )

    def test_fixed_message_scaffolding_is_counted(self):
        # known_overhead_chars must include the exact system prompt length
        # and the exact fixed header strings generate_patch_raw() sends --
        # not just "some overhead", the REAL strings.
        cap = compute_patch_generation_capacity("v")
        system_prompt_len = len(_PROMPT_PATH.read_text(encoding="utf-8"))
        expected_min_overhead = system_prompt_len + len(_VULN_HEADER) + len("v") + len(_CODE_CONTEXT_HEADER)
        assert cap.known_overhead_chars == expected_min_overhead

    def test_retry_hint_absent_by_default_matches_initial_call_shape(self):
        # retry_hint="" (the default) must NOT add _RETRY_HEADER overhead --
        # generate_patch_raw() only ever adds that header `if retry_hint:`.
        cap_no_hint = compute_patch_generation_capacity("v")
        cap_empty_hint = compute_patch_generation_capacity("v", retry_hint="")
        assert cap_no_hint.known_overhead_chars == cap_empty_hint.known_overhead_chars

    def test_retry_hint_and_its_scaffolding_reduce_available_capacity(self):
        hint = "y" * 5_000
        cap_no_hint = compute_patch_generation_capacity("v")
        cap_with_hint = compute_patch_generation_capacity("v", retry_hint=hint)
        assert cap_with_hint.source_capacity_chars < cap_no_hint.source_capacity_chars
        assert (
            cap_no_hint.known_overhead_chars
            == cap_with_hint.known_overhead_chars - len(_RETRY_HEADER) - len(hint)
        )

    def test_calculation_matches_the_actual_strings_generate_patch_raw_sends(self):
        # The overhead this function counts (system prompt + _VULN_HEADER +
        # vulnerability_text + _CODE_CONTEXT_HEADER + _RETRY_HEADER + hint)
        # must correspond EXACTLY to what generate_patch_raw() assembles,
        # modulo `code_context` itself (the one variable this contract is
        # sizing). Verified by reconstructing the real user_message length
        # generate_patch_raw() would produce for a given code_context and
        # checking it never exceeds system_prompt + capacity's own
        # accounting once code_context is held to the reported ceiling.
        vuln, hint = "some vulnerability text", "some retry hint"
        cap = compute_patch_generation_capacity(vuln, retry_hint=hint)
        code_context = "z" * cap.source_capacity_chars
        system_prompt = _PROMPT_PATH.read_text(encoding="utf-8")
        user_message = _VULN_HEADER + vuln
        user_message += _CODE_CONTEXT_HEADER + code_context
        user_message += _RETRY_HEADER + hint
        total_request_chars = len(system_prompt) + len(user_message)
        # available_input_chars = (context_window - reserved_output - safety_margin) * chars_per_token
        available_input_chars = (
            (cap.context_window_tokens - cap.reserved_output_tokens - cap.safety_margin_tokens)
            * cap.chars_per_token_ratio
        )
        assert total_request_chars <= available_input_chars


class TestFitPatchGenerationContextWholeBlockDiscipline:
    def _sections(self):
        return [
            ("plan_text", "PLAN" * 100),
            ("repo_code", "CODE" * 100),
            (PATCH_GENERATION_REQUIRED_LABEL, "SLICE" * 100),
            ("coverage_warning", "WARN" * 100),
        ]

    def test_all_sections_included_when_capacity_is_generous(self):
        sections = self._sections()
        plan = fit_patch_generation_context(sections, max_chars=100_000, required_label=PATCH_GENERATION_REQUIRED_LABEL)
        assert plan.required_missing is False
        assert set(plan.included_labels) == {label for label, _ in sections}
        assert plan.omission_reason == {}
        for label, text in sections:
            assert text in plan.rendered

    def test_optional_sections_never_truncated_mid_string_only_whole_or_absent(self):
        sections = self._sections()
        # Small enough that not everything fits, large enough that the
        # required block + at least one optional one does.
        required_len = len("SLICE" * 100)
        plan = fit_patch_generation_context(
            sections, max_chars=required_len + 50, required_label=PATCH_GENERATION_REQUIRED_LABEL,
        )
        for label, text in sections:
            if label in plan.omission_reason:
                assert text not in plan.rendered
            else:
                # Included -- must appear WHOLE, never a partial prefix/suffix.
                assert text in plan.rendered

    def test_omitted_optional_section_recorded_with_technical_capacity_reason(self):
        sections = self._sections()
        required_len = len("SLICE" * 100)
        plan = fit_patch_generation_context(
            sections, max_chars=required_len + 5, required_label=PATCH_GENERATION_REQUIRED_LABEL,
        )
        assert plan.required_missing is False
        assert plan.omission_reason  # at least one optional section didn't fit
        for label, reason in plan.omission_reason.items():
            assert reason == "technical_capacity"
            assert label in plan.omitted_sizes
            assert plan.omitted_sizes[label] == len(dict(sections)[label])

    def test_required_label_reserved_first_never_dropped_for_an_earlier_optional_section(self):
        # An optional section BEFORE the required one in the list must not
        # be able to "win" the room the required one needs.
        sections = [
            ("early_optional", "E" * 90_000),
            (PATCH_GENERATION_REQUIRED_LABEL, "R" * 1_000),
        ]
        plan = fit_patch_generation_context(sections, max_chars=1_000, required_label=PATCH_GENERATION_REQUIRED_LABEL)
        assert plan.required_missing is False
        assert "early_optional" in plan.omission_reason
        assert "R" * 1_000 in plan.rendered

    def test_required_missing_when_required_block_alone_exceeds_capacity(self):
        sections = self._sections()
        required_len = len("SLICE" * 100)
        plan = fit_patch_generation_context(
            sections, max_chars=required_len - 1, required_label=PATCH_GENERATION_REQUIRED_LABEL,
        )
        assert plan.required_missing is True
        assert plan.rendered == ""
        assert plan.omitted_sizes.get(PATCH_GENERATION_REQUIRED_LABEL) == required_len

    def test_no_required_label_just_greedily_fits_optional_sections_in_order(self):
        sections = [("a", "A" * 10), ("b", "B" * 10), ("c", "C" * 10)]
        plan = fit_patch_generation_context(sections, max_chars=25, required_label=None)
        assert plan.required_missing is False
        # "a" (10) + sep? no sep yet + "b" (10) = 20 <= 25; "c" would need
        # 2 (sep) + 10 = 12 more -> 32 > 25, so "c" is omitted.
        assert "a" in plan.included_labels
        assert "b" in plan.included_labels
        assert "c" not in plan.included_labels
        assert plan.omission_reason == {"c": "technical_capacity"}

    def test_combined_rendered_length_never_exceeds_max_chars(self):
        sections = self._sections()
        for ceiling in (0, 10, 100, 500, 2_000, 1_000_000):
            plan = fit_patch_generation_context(sections, max_chars=ceiling, required_label=PATCH_GENERATION_REQUIRED_LABEL)
            assert len(plan.rendered) <= ceiling

    def test_empty_or_blank_sections_are_dropped_and_never_labeled_omitted(self):
        sections = [("blank", "   "), ("empty", ""), (PATCH_GENERATION_REQUIRED_LABEL, "REQUIRED")]
        plan = fit_patch_generation_context(sections, max_chars=1_000, required_label=PATCH_GENERATION_REQUIRED_LABEL)
        assert "blank" not in plan.included_labels
        assert "empty" not in plan.included_labels
        assert "blank" not in plan.omission_reason
        assert "empty" not in plan.omission_reason

    def test_included_sections_preserve_relative_order_for_rebuilding(self):
        sections = self._sections()
        plan = fit_patch_generation_context(sections, max_chars=100_000, required_label=PATCH_GENERATION_REQUIRED_LABEL)
        assert [label for label, _ in plan.included_sections] == [label for label, _ in sections]


class TestGeneratePatchRawUsesSharedScaffolding:
    def test_generate_patch_raw_wraps_with_the_same_constants_capacity_counts(self):
        captured = {}

        class _FakeLLM:
            def complete(self, system_prompt, user_message, stage=None):
                captured["system_prompt"] = system_prompt
                captured["user_message"] = user_message
                return "```diff\n--- a\n+++ b\n```"

        generate_patch_raw("VULN_TEXT", _FakeLLM(), code_context="CODE_CTX", retry_hint="HINT_TEXT")
        assert captured["user_message"] == (
            _VULN_HEADER + "VULN_TEXT" + _CODE_CONTEXT_HEADER + "CODE_CTX" + _RETRY_HEADER + "HINT_TEXT"
        )
