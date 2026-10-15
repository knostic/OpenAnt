"""Focused tests for the experimental Simple Concern Resolver's own
harness -- archived-run extraction/isolation and output shape. NOT an
end-to-end/live-LLM test suite (see `simple_concern_harness.py --mock` for
a manual plumbing self-check)."""

from __future__ import annotations

import json
from unittest import mock

from utilities.autopatcher.tools.simple_concern_harness import (
    run_simple_only, main, _MockLLM, _strip_target_discovery_plan,
)
from utilities.autopatcher.tools.concern_tree_harness import extract_archived_concerns


# Generic, non-urllib3 synthetic fixture representing the exact structural
# shape of a real archived `code_context`: a genuinely deterministic
# "Repository Understanding" section, Planning's own prior-interpretation
# "Target Discovery Plan" narrative section (the one this filter removes),
# and a genuinely deterministic "Final-Target Remediation Slice" section.
_SYNTHETIC_CODE_CONTEXT_WITH_PLAN = (
    "## Repository Understanding\n\n"
    "*Deterministic repository analysis, not a vulnerability verdict.*\n\n"
    "### `mod.py`\n\n"
    "- Grounding: best tier 2\n\n"
    "## Target Discovery Plan (exploratory — not authoritative for Patch Generation)\n\n"
    "**Security invariant:** some prior narrative claim about the fix.\n\n"
    "**Likely remediation mechanism:** some prior narrative claim about the mechanism.\n\n"
    "**Explicit unknowns:**\n"
    "- some prior narrative claim about what is unresolved.\n\n"
    "## Final-Target Remediation Slice\n\n"
    "*Deterministic, bounded repository source, verbatim.*\n\n"
    "#### Target definition: `mod.py:widget` (lines 1-5)\n\n"
    "```python\n"
    "def widget():\n"
    "    op()\n"
    "```\n"
)


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


class TestArchivedExtraction:
    def test_extracts_only_role_and_description(self):
        """Item 29 -- the harness extracts only concern role + description
        from the archived response, never any v2 resolution field."""
        archived, skipped = extract_archived_concerns(_SYNTHETIC_ARCHIVED_RESPONSE)
        assert skipped == []
        assert len(archived) == 1
        assert set(archived[0].keys()) == {"concern_number", "concern_role", "description"}
        assert "default_execution_reachability" not in archived[0]

    def test_run_simple_only_never_exposes_v2_resolution_fields(self):
        """Item 30 -- `strip_to_experimental_input`'s own leak-guard
        applies here exactly as it does for the Tree, since it is reused
        unchanged, not reimplemented."""
        archived, _ = extract_archived_concerns(_SYNTHETIC_ARCHIVED_RESPONSE)
        result = run_simple_only("if flag: raise Err()\nop()", "", _MockLLM(), archived)
        for c in result["concerns"]:
            assert "default_execution_reachability" not in c
            assert "consequence" not in c
            assert "malformed" not in c

    @staticmethod
    def _code_without_module_docstring() -> str:
        """The module's source with its own top-level docstring stripped
        -- that docstring legitimately DISCUSSES `vulnerability_text`/
        `concern_tree.py` in prose (explaining what is NOT read/imported),
        so the isolation checks below inspect only the executable code
        that follows it, not that explanatory prose."""
        import ast
        import inspect
        from utilities.autopatcher.tools import simple_concern_harness as harness_mod
        src = inspect.getsource(harness_mod)
        tree = ast.parse(src)
        if tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Constant):
            lines = src.splitlines()
            return "\n".join(lines[tree.body[0].end_lineno:])
        return src

    def test_harness_never_reads_vulnerability_text_into_any_variable(self):
        """Item 31 -- `vulnerability_text`, recovered from the prompt
        trace as an implementation detail of `parse_challenger_prompt_
        trace`, is never read into any variable this harness passes
        onward to either semantic pass."""
        code_only = self._code_without_module_docstring()
        assert "vulnerability_text" not in code_only

    def test_harness_does_not_read_tree_result_artifacts(self):
        """Item 32 -- no reference to Tree result filenames/keys anywhere
        in this harness's actual CODE; comparison happens offline, outside
        this file."""
        code_only = self._code_without_module_docstring()
        assert "tree-results" not in code_only
        assert "tree_results" not in code_only
        assert "tree-comparison" not in code_only
        assert "evaluate_concern_tree" not in code_only


class TestOutputShape:
    def test_output_artifact_is_linear_not_graph_shaped(self):
        """Item 33 -- no node-graph keys anywhere in the per-concern
        record; a fixed, flat set of keys regardless of what happened."""
        archived, _ = extract_archived_concerns(_SYNTHETIC_ARCHIVED_RESPONSE)
        result = run_simple_only("if flag: raise Err()\nop()", "", _MockLLM(), archived)
        assert result["mode"] == "simple_only"
        for c in result["concerns"]:
            assert "children" not in c
            assert "nodes" not in c
            assert "depth" not in c
            assert "parent_id" not in c
            assert set(c.keys()) == {
                "concern_number", "concern_role", "concern_description", "final_verdict",
                "unresolved_reason", "citations", "pass1", "acquisition", "pass1_rerun",
                "pass2", "metrics",
            }

    def test_metrics_correctly_count_calls_acquisition_and_provenance(self, tmp_path):
        """Item 34."""
        (tmp_path / "mod.py").write_text("op()\n")
        archived, _ = extract_archived_concerns(_SYNTHETIC_ARCHIVED_RESPONSE)

        class _AcquiringLLM:
            def __init__(self):
                self.n = 0

            def complete(self, system_prompt, user_message, stage=None, **_kwargs):
                self.n += 1
                if self.n == 1:
                    return (
                        "Candidate verdict: UNRESOLVED\nReasoning: need to see it\nCitations:\n"
                        "Missing evidence: needed\nRequest type: file_source\nFile hint: mod.py\nSymbol: none\n"
                    )
                if self.n == 2:
                    return "Candidate verdict: PROVEN\nReasoning: r\nCitations:\n- op()\nMissing evidence: none\n"
                return "Challenge result: c\nFinal verdict: PROVEN\nFinal reasoning: r\nCitations:\n- op()\n"

        result = run_simple_only(
            "", "", _AcquiringLLM(), archived, repo_root=tmp_path, investigation_context=object(),
        )
        c = result["concerns"][0]
        assert c["metrics"]["llm_calls"] == 3
        assert c["metrics"]["evidence_requests"] == 1
        assert c["metrics"]["evidence_acquired"] == 1
        assert c["metrics"]["invalid_provenance_count"] == 0
        assert c["final_verdict"] == "PROVEN"


class TestTargetDiscoveryPlanFilter:
    """Unit tests for `_strip_target_discovery_plan` -- the ONE change
    this experiment makes. Purely structural: locates Planning's own
    "## Target Discovery Plan" heading and removes exactly that section,
    up to (never including) the next peer-level "## " heading. Uses only
    generic synthetic content -- no urllib3/Cookie/assert_same_host/
    HostChangedError/remove_headers_on_redirect strings anywhere, and the
    filter itself never inspects section CONTENT, only the heading
    boundary."""

    def test_removes_target_discovery_plan_section(self):
        """Item 1."""
        result = _strip_target_discovery_plan(_SYNTHETIC_CODE_CONTEXT_WITH_PLAN)
        assert "## Target Discovery Plan" not in result
        assert "Security invariant" not in result
        assert "Explicit unknowns" not in result

    def test_preserves_preceding_evidence_byte_for_byte(self):
        """Item 2."""
        result = _strip_target_discovery_plan(_SYNTHETIC_CODE_CONTEXT_WITH_PLAN)
        preceding = _SYNTHETIC_CODE_CONTEXT_WITH_PLAN.split("## Target Discovery Plan")[0]
        assert result.startswith(preceding)
        assert "## Repository Understanding" in result
        assert "Grounding: best tier 2" in result

    def test_preserves_following_evidence_byte_for_byte(self):
        """Item 3."""
        result = _strip_target_discovery_plan(_SYNTHETIC_CODE_CONTEXT_WITH_PLAN)
        following_start = _SYNTHETIC_CODE_CONTEXT_WITH_PLAN.index("## Final-Target Remediation Slice")
        following = _SYNTHETIC_CODE_CONTEXT_WITH_PLAN[following_start:]
        assert result.endswith(following)

    def test_does_not_over_consume_next_section(self):
        """Item 4 -- the next peer-level heading and its full body must
        remain intact, not just its heading line."""
        result = _strip_target_discovery_plan(_SYNTHETIC_CODE_CONTEXT_WITH_PLAN)
        assert "## Final-Target Remediation Slice" in result
        assert "Target definition: `mod.py:widget`" in result
        assert "def widget():" in result
        assert "op()" in result

    def test_absent_section_returns_input_unchanged(self):
        """Item 5."""
        clean = "## Repository Understanding\n\nsome text\n\n## Final-Target Remediation Slice\n\nmore text\n"
        assert _strip_target_discovery_plan(clean) == clean

    def test_empty_and_none_input_returns_unchanged(self):
        assert _strip_target_discovery_plan("") == ""
        assert _strip_target_discovery_plan(None) is None

    def test_fixture_content_is_generic_not_run1_specific(self):
        """Item 6 -- guards the test fixture itself, not just the filter,
        against ever encoding Run 1-specific facts."""
        for forbidden in (
            "urllib3", "Cookie", "assert_same_host", "HostChangedError", "remove_headers_on_redirect",
        ):
            assert forbidden not in _SYNTHETIC_CODE_CONTEXT_WITH_PLAN

    def test_only_removes_first_matching_section_boundary_once(self):
        """A heading appearing without a following peer heading at all
        (end of string) is removed cleanly to the end -- exercises the
        `next_match is None` branch."""
        no_trailing_section = (
            "## Repository Understanding\n\nkept text\n\n"
            "## Target Discovery Plan (exploratory)\n\n**Explicit unknowns:**\n- x\n"
        )
        result = _strip_target_discovery_plan(no_trailing_section)
        assert "kept text" in result
        assert "Target Discovery Plan" not in result
        assert "Explicit unknowns" not in result


class TestHarnessBoundaryFiltering:
    def test_run_simple_only_passes_filtered_code_context_to_resolver(self):
        """Item 7 -- proves the filtered `code_context` (not the raw one)
        is what actually reaches `resolve_concern`, while the concern's
        own proposition and the patch text are passed through unchanged.
        `resolve_concern` itself is replaced with a recording stub, so
        this exercises no real/semantic LLM behavior at all."""
        archived_concerns = [
            {"concern_number": 1, "concern_role": "primary", "description": "the raw concern description"},
        ]
        captured = {}

        def _fake_resolve_concern(proposition, code_context, patch, llm, **kwargs):
            captured["proposition"] = proposition
            captured["code_context"] = code_context
            captured["patch"] = patch
            return {
                "final_verdict": "UNRESOLVED", "unresolved_reason": "model_reported_unresolved",
                "citations": [], "pass1": None, "acquisition": None, "pass1_rerun": None, "pass2": None,
                "metrics": {"llm_calls": 0, "evidence_requests": 0, "evidence_acquired": 0, "invalid_provenance_count": 0},
            }

        with mock.patch(
            "utilities.autopatcher.tools.simple_concern_harness.resolve_concern",
            side_effect=_fake_resolve_concern,
        ):
            run_simple_only(
                _SYNTHETIC_CODE_CONTEXT_WITH_PLAN, "some patch text", _MockLLM(), archived_concerns,
            )

        assert "## Target Discovery Plan" not in captured["code_context"]
        assert "## Repository Understanding" in captured["code_context"]
        assert "## Final-Target Remediation Slice" in captured["code_context"]
        assert captured["proposition"] == "the raw concern description"
        assert captured["patch"] == "some patch text"


class TestCLI:
    def test_main_mock_mode_writes_linear_artifact(self, tmp_path):
        prompt_file = tmp_path / "p.txt"
        response_file = tmp_path / "r.txt"
        prompt_file.write_text(_SYNTHETIC_PROMPT_TRACE)
        response_file.write_text(_SYNTHETIC_ARCHIVED_RESPONSE)
        output = tmp_path / "out.json"

        rc = main([
            "--challenger-prompt-file", str(prompt_file),
            "--challenger-response-file", str(response_file),
            "--output", str(output),
            "--mock",
        ])
        assert rc == 0
        result = json.loads(output.read_text())
        assert result["mode"] == "simple_only"
        assert result["archived_concern_count"] == 1
        assert result["concerns"][0]["final_verdict"] == "UNRESOLVED"
