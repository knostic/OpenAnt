"""Unit tests for the experimental Simple Concern Resolver
(`utilities.autopatcher.simple_concern_resolver`) -- an isolated two-pass
(Analyze -> Challenge+Finalize) A/B alternative to the recursive Concern
Tree. These tests exercise ONLY this module, using a mocked/stubbed LLM
throughout (no live LLM calls). `test_concern_tree.py` and
`test_patch_challenger.py` are run separately, unmodified, to confirm
neither the Tree nor concerns_v2 baseline behavior is touched by this
module's existence (see the completion report; not duplicated here)."""

from __future__ import annotations

from pathlib import Path
from unittest import mock

from utilities.autopatcher.simple_concern_resolver import (
    resolve_concern,
    parse_pass1,
    parse_pass2,
    VERDICTS,
    _point_citation_valid,
    _render_pass1_result,
    Pass1Result,
)


def _llm(*responses):
    m = mock.MagicMock()
    m.complete.side_effect = list(responses)
    return m


def _pass1(verdict="PROVEN", reasoning="established", citation="op()"):
    return (
        f"Candidate verdict: {verdict}\nReasoning: {reasoning}\nCitations:\n- {citation}\n"
        f"Missing evidence: none\n"
    )


def _pass1_unresolved(reasoning="cannot tell from what is shown"):
    return f"Candidate verdict: UNRESOLVED\nReasoning: {reasoning}\nCitations:\nMissing evidence: none\n"


def _pass1_missing(request_type="file_source", file_hint="mod.py", symbol="none",
                    reasoning="need to see the definition"):
    return (
        f"Candidate verdict: UNRESOLVED\nReasoning: {reasoning}\nCitations:\n"
        f"Missing evidence: needed\nRequest type: {request_type}\nFile hint: {file_hint}\nSymbol: {symbol}\n"
    )


def _pass2(verdict="PROVEN", challenge="checked thoroughly, candidate holds", reasoning="confirmed",
           citation="op()"):
    return (
        f"Challenge result: {challenge}\nFinal verdict: {verdict}\n"
        f"Final reasoning: {reasoning}\nCitations:\n- {citation}\n"
    )


def _pass2_unresolved(challenge="found a material tension I cannot resolve", reasoning="cannot responsibly choose"):
    return f"Challenge result: {challenge}\nFinal verdict: UNRESOLVED\nFinal reasoning: {reasoning}\nCitations:\n"


class TestBasicFlow:
    def test_pass1_proven_no_missing_evidence_invokes_pass2(self):
        """Item 1."""
        llm = _llm(_pass1(verdict="PROVEN", citation="op()"), _pass2(verdict="PROVEN", citation="op()"))
        result = resolve_concern("op occurs", code_context="op()", patch="", llm=llm)
        assert result["final_verdict"] == "PROVEN"
        assert result["pass2"] is not None
        assert result["metrics"]["llm_calls"] == 2

    def test_pass1_refuted_no_missing_evidence_invokes_pass2(self):
        """Item 2."""
        llm = _llm(_pass1(verdict="REFUTED", citation="raise Err()"), _pass2(verdict="REFUTED", citation="raise Err()"))
        result = resolve_concern("op occurs", code_context="raise Err()", patch="", llm=llm)
        assert result["final_verdict"] == "REFUTED"
        assert result["pass2"] is not None
        assert result["metrics"]["llm_calls"] == 2

    def test_pass1_unresolved_no_missing_evidence_still_invokes_pass2(self):
        """Item 3 -- Pass 2 is a genuine second opinion, not a gate that
        only fires when Pass 1 produced a real verdict."""
        llm = _llm(_pass1_unresolved(), _pass2(verdict="PROVEN", citation="op()"))
        result = resolve_concern("op occurs", code_context="op()", patch="", llm=llm)
        assert result["pass2"] is not None
        assert result["final_verdict"] == "PROVEN"
        assert result["metrics"]["llm_calls"] == 2


class TestPass2CanChangeVerdict:
    def test_pass2_preserves_pass1_verdict(self):
        """Item 4."""
        llm = _llm(_pass1(verdict="PROVEN", citation="op()"), _pass2(verdict="PROVEN", citation="op()"))
        result = resolve_concern("x", code_context="op()", patch="", llm=llm)
        assert result["final_verdict"] == "PROVEN"

    def test_pass2_overturns_proven_to_refuted(self):
        """Item 5."""
        llm = _llm(
            _pass1(verdict="PROVEN", citation="op()"),
            _pass2(verdict="REFUTED", challenge="found a condition the first pass missed", citation="raise Err()"),
        )
        result = resolve_concern("x", code_context="op()\nraise Err()", patch="", llm=llm)
        assert result["final_verdict"] == "REFUTED"

    def test_pass2_overturns_refuted_to_proven(self):
        """Item 6."""
        llm = _llm(
            _pass1(verdict="REFUTED", citation="raise Err()"),
            _pass2(verdict="PROVEN", challenge="the cited exception is unreachable here", citation="op()"),
        )
        result = resolve_concern("x", code_context="op()\nraise Err()", patch="", llm=llm)
        assert result["final_verdict"] == "PROVEN"

    def test_pass2_changes_proven_to_unresolved(self):
        """Item 7."""
        llm = _llm(_pass1(verdict="PROVEN", citation="op()"), _pass2_unresolved())
        result = resolve_concern("x", code_context="op()", patch="", llm=llm)
        assert result["final_verdict"] == "UNRESOLVED"

    def test_pass2_changes_refuted_to_unresolved(self):
        """Item 7 (companion)."""
        llm = _llm(_pass1(verdict="REFUTED", citation="raise Err()"), _pass2_unresolved())
        result = resolve_concern("x", code_context="raise Err()", patch="", llm=llm)
        assert result["final_verdict"] == "UNRESOLVED"


class TestPass2OutputOrderAndCitations:
    def test_final_verdict_before_challenge_result_fails_closed(self):
        """Item 8."""
        raw = "Final verdict: PROVEN\nChallenge result: c\nFinal reasoning: r\nCitations:\n- x\n"
        action = parse_pass2(raw)
        assert action.kind == "INVALID"
        assert action.invalid_detail == "wrong_order"

    def test_challenge_result_before_final_verdict_parses(self):
        raw = "Challenge result: c\nFinal verdict: PROVEN\nFinal reasoning: r\nCitations:\n- x\n"
        action = parse_pass2(raw)
        assert action.kind == "PROVEN"

    def test_pass2_citations_independently_validated_not_inherited(self):
        """Item 9 -- Pass 1's own (valid) citation does not make Pass 2's
        own (bogus) citation pass; Pass 2 must independently establish
        its own verdict."""
        llm = _llm(
            _pass1(verdict="PROVEN", citation="op()"),
            _pass2(verdict="PROVEN", citation="this text is not present anywhere"),
        )
        result = resolve_concern("x", code_context="op()", patch="", llm=llm)
        assert result["final_verdict"] == "UNRESOLVED"
        assert result["unresolved_reason"] == "invalid_provenance"


class TestEvidenceAcquisition:
    def test_valid_evidence_request_triggers_one_acquisition_attempt(self, tmp_path):
        """Item 10."""
        (tmp_path / "mod.py").write_text("op()\n")
        llm = _llm(
            _pass1_missing(file_hint="mod.py"),
            _pass1(verdict="PROVEN", citation="op()"),
            _pass2(verdict="PROVEN", citation="op()"),
        )
        result = resolve_concern(
            "x", code_context="", patch="", llm=llm, repo_root=tmp_path, investigation_context=object(),
        )
        assert result["metrics"]["evidence_requests"] == 1
        assert result["acquisition"]["resolved"] is True

    def test_successful_acquisition_triggers_exactly_one_pass1_rerun(self, tmp_path):
        """Item 11."""
        (tmp_path / "mod.py").write_text("op()\n")
        llm = _llm(
            _pass1_missing(file_hint="mod.py"),
            _pass1(verdict="PROVEN", citation="op()"),
            _pass2(verdict="PROVEN", citation="op()"),
        )
        result = resolve_concern(
            "x", code_context="", patch="", llm=llm, repo_root=tmp_path, investigation_context=object(),
        )
        assert result["pass1_rerun"] is not None
        assert result["metrics"]["llm_calls"] == 3
        assert result["metrics"]["evidence_acquired"] == 1

    def test_pass1_rerun_resolves_invokes_pass2(self, tmp_path):
        """Item 12."""
        (tmp_path / "mod.py").write_text("op()\n")
        llm = _llm(
            _pass1_missing(file_hint="mod.py"),
            _pass1(verdict="REFUTED", citation="op()"),
            _pass2(verdict="REFUTED", citation="op()"),
        )
        result = resolve_concern(
            "x", code_context="", patch="", llm=llm, repo_root=tmp_path, investigation_context=object(),
        )
        assert result["pass2"] is not None
        assert result["final_verdict"] == "REFUTED"

    def test_pass1_rerun_still_requests_evidence_finalizes_unresolved_no_pass2(self, tmp_path):
        """Item 13."""
        (tmp_path / "mod.py").write_text("op()\n")
        llm = _llm(
            _pass1_missing(file_hint="mod.py"),
            _pass1_missing(file_hint="other.py", reasoning="still need more"),
        )
        result = resolve_concern(
            "x", code_context="", patch="", llm=llm, repo_root=tmp_path, investigation_context=object(),
        )
        assert result["final_verdict"] == "UNRESOLVED"
        assert result["unresolved_reason"] == "no_progress"
        assert result["pass2"] is None
        assert result["metrics"]["llm_calls"] == 2

    def test_acquisition_failure_finalizes_unresolved_no_pass2(self, tmp_path):
        """Item 14."""
        llm = _llm(_pass1_missing(file_hint="does_not_exist.py"))
        result = resolve_concern(
            "x", code_context="", patch="", llm=llm, repo_root=tmp_path, investigation_context=object(),
        )
        assert result["final_verdict"] == "UNRESOLVED"
        assert result["pass2"] is None
        assert result["metrics"]["llm_calls"] == 1

    def test_no_repo_root_fails_closed_no_pass2(self):
        llm = _llm(_pass1_missing(file_hint="mod.py"))
        result = resolve_concern("x", code_context="", patch="", llm=llm)
        assert result["final_verdict"] == "UNRESOLVED"
        assert result["acquisition"]["failure_reason"] == "no_repo_root"
        assert result["pass2"] is None


class TestStructuralGates:
    def test_invalid_evidence_request_fails_closed(self):
        """Item 15 -- symbol_definition with no Symbol named."""
        raw = (
            "Candidate verdict: UNRESOLVED\nReasoning: r\nCitations:\nMissing evidence: needed\n"
            "Request type: symbol_definition\nFile hint: mod.py\nSymbol: none\n"
        )
        action = parse_pass1(raw)
        assert action.kind == "INVALID"

    def test_missing_evidence_needed_with_proven_verdict_fails_closed(self):
        """Item 16."""
        raw = (
            "Candidate verdict: PROVEN\nReasoning: r\nCitations:\n- x\nMissing evidence: needed\n"
            "Request type: file_source\nFile hint: mod.py\nSymbol: none\n"
        )
        action = parse_pass1(raw)
        assert action.kind == "INVALID"
        assert action.invalid_detail == "missing_evidence_requires_unresolved_verdict"

    def test_missing_evidence_needed_with_refuted_verdict_fails_closed(self):
        raw = (
            "Candidate verdict: REFUTED\nReasoning: r\nCitations:\n- x\nMissing evidence: needed\n"
            "Request type: file_source\nFile hint: mod.py\nSymbol: none\n"
        )
        action = parse_pass1(raw)
        assert action.kind == "INVALID"


class TestComplexityCeiling:
    def test_no_more_than_three_llm_calls(self, tmp_path):
        """Item 17."""
        (tmp_path / "mod.py").write_text("op()\n")
        llm = _llm(
            _pass1_missing(file_hint="mod.py"),
            _pass1(verdict="PROVEN", citation="op()"),
            _pass2(verdict="PROVEN", citation="op()"),
        )
        result = resolve_concern(
            "x", code_context="", patch="", llm=llm, repo_root=tmp_path, investigation_context=object(),
        )
        assert result["metrics"]["llm_calls"] <= 3
        assert llm.complete.call_count == 3

    def test_no_more_than_one_acquisition_possible(self, tmp_path):
        """Item 18 -- a second Pass-1 request is never itself acquired."""
        (tmp_path / "mod.py").write_text("op()\n")
        (tmp_path / "other.py").write_text("op()\n")
        llm = _llm(_pass1_missing(file_hint="mod.py"), _pass1_missing(file_hint="other.py"))
        result = resolve_concern(
            "x", code_context="", patch="", llm=llm, repo_root=tmp_path, investigation_context=object(),
        )
        assert result["metrics"]["evidence_requests"] == 1
        assert result["metrics"]["evidence_acquired"] == 1
        assert llm.complete.call_count == 2


class TestMalformedOutput:
    def test_malformed_pass1_is_unresolved(self):
        """Item 19."""
        llm = _llm("no recognizable fields here at all")
        result = resolve_concern("x", code_context="op()", patch="", llm=llm)
        assert result["final_verdict"] == "UNRESOLVED"
        assert result["unresolved_reason"] == "invalid_output"
        assert result["pass2"] is None

    def test_malformed_pass2_is_unresolved(self):
        """Item 20."""
        llm = _llm(_pass1(verdict="PROVEN", citation="op()"), "no recognizable fields here at all")
        result = resolve_concern("x", code_context="op()", patch="", llm=llm)
        assert result["final_verdict"] == "UNRESOLVED"
        assert result["unresolved_reason"] == "invalid_output"


class TestProvenance:
    def test_invalid_pass1_provenance_does_not_block_pass2(self):
        """Item 21 -- Pass 1's own bogus citation is tracked but never
        gates whether Pass 2 runs; Pass 2 independently re-establishes
        with a valid citation of its own."""
        llm = _llm(
            _pass1(verdict="PROVEN", citation="fabricated, not present anywhere"),
            _pass2(verdict="PROVEN", citation="op()"),
        )
        result = resolve_concern("x", code_context="op()", patch="", llm=llm)
        assert result["final_verdict"] == "PROVEN"
        assert result["metrics"]["invalid_provenance_count"] == 1

    def test_invalid_pass2_provenance_finalizes_unresolved(self):
        """Item 22."""
        llm = _llm(_pass1(verdict="PROVEN", citation="op()"), _pass2(verdict="PROVEN", citation="fabricated text"))
        result = resolve_concern("x", code_context="op()", patch="", llm=llm)
        assert result["final_verdict"] == "UNRESOLVED"
        assert result["unresolved_reason"] == "invalid_provenance"
        assert result["metrics"]["invalid_provenance_count"] == 1


class TestIsolation:
    def test_citation_validator_is_the_unchanged_production_function(self):
        """Item 23."""
        from utilities.autopatcher import patch_challenger as pc
        assert _point_citation_valid is pc._point_citation_valid

    def test_resolver_does_not_import_concern_tree(self):
        """Item 24 -- no actual import statement references concern_tree
        (the module docstring legitimately DISCUSSES it in prose, e.g.
        "Does NOT depend on concern_tree.py", so this checks import
        lines specifically, not the whole file text)."""
        import ast
        src = Path("utilities/autopatcher/simple_concern_resolver.py").read_text()
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert node.module is None or "concern_tree" not in node.module
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    assert "concern_tree" not in alias.name

    def test_resolver_does_not_import_pipeline(self):
        """Item 25 -- same import-statement-only check as above."""
        import ast
        src = Path("utilities/autopatcher/simple_concern_resolver.py").read_text()
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert node.module is None or "pipeline" not in node.module
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    assert "pipeline" not in alias.name

    def test_resolver_only_imports_provenance_helpers_from_patch_challenger(self):
        """Item 26."""
        import ast
        src = Path("utilities/autopatcher/simple_concern_resolver.py").read_text()
        provenance_helpers = {"_point_citation_valid", "_normalize_for_provenance", "_strip_quote_wrapping"}
        imported = set()
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.ImportFrom) and node.module == "patch_challenger":
                assert node.level == 1
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and "patch_challenger" in node.module:
                raise AssertionError(f"unexpected patch_challenger import form: {node.module}")
            elif isinstance(node, ast.Import):
                assert not any("patch_challenger" in alias.name for alias in node.names)
        assert "_point_citation_valid" in imported
        assert imported <= provenance_helpers, imported - provenance_helpers

    def test_no_production_module_imports_simple_concern_resolver(self):
        challenger_src = Path("utilities/autopatcher/patch_challenger.py").read_text()
        pipeline_src = Path("utilities/autopatcher/pipeline.py").read_text()
        assert "simple_concern_resolver" not in challenger_src
        assert "simple_concern_resolver" not in pipeline_src

    def test_concern_tree_module_unmodified_untouched(self):
        """This module must never be imported BY concern_tree.py either --
        the two experiments are siblings, not layered."""
        tree_src = Path("utilities/autopatcher/concern_tree.py").read_text()
        assert "simple_concern_resolver" not in tree_src


class TestPromptContent:
    def _analyze_text(self):
        from utilities.autopatcher.simple_concern_resolver import _PASS1_PROMPT_PATH
        return _PASS1_PROMPT_PATH.read_text(encoding="utf-8")

    def _challenge_text(self):
        from utilities.autopatcher.simple_concern_resolver import _PASS2_PROMPT_PATH
        return _PASS2_PROMPT_PATH.read_text(encoding="utf-8")

    def test_prompts_contain_no_mechanism_taxonomy(self):
        """Item 27."""
        for text in (self._analyze_text(), self._challenge_text()):
            lowered = text.lower()
            for forbidden in (
                "control flow", "control-flow", "data flow", "data-flow",
                "state transition", "ordering complete", "parser complete", "config_complete",
            ):
                assert forbidden not in lowered

    def test_prompts_contain_no_decomposition_or_recursion_instructions(self):
        """Item 28."""
        for text in (self._analyze_text(), self._challenge_text()):
            lowered = text.lower()
            assert "decompose" not in lowered
            assert "child" not in lowered
            assert "recursi" not in lowered

    def test_prompts_forbid_split_joined_escaped_or_paraphrased_citations(self):
        for text in (self._analyze_text(), self._challenge_text()):
            assert "never split one span across" in text
            assert "never combine two separate spans into" in text
            assert "never paraphrase, summarize, or reconstruct from memory" in text

    def test_prompts_forbid_quote_or_backtick_delimiting_of_citations(self):
        """Bare Citation Protocol: the old permission for citations to be
        "visually delimited by quotes or backticks" must be gone, replaced
        by an explicit prohibition on adding any delimiter at all -- this
        is the root-cause fix for the escaped-inner-quote failure observed
        on the real archived Run 1 (a source line containing quote
        characters, wrapped by the model in double quotes and escaped)."""
        for text in (self._analyze_text(), self._challenge_text()):
            assert "visually delimited by quotes or backticks" not in text
            assert "do NOT surround the citation with quotes, backticks" in text

    def test_prompts_contain_bare_citation_worked_example(self):
        """Locks in the compact worked example demonstrating the exact
        failure mode observed on Run 1 -- a correct bare citation next to
        the incorrect, backslash-escaped, quote-wrapped form."""
        for text in (self._analyze_text(), self._challenge_text()):
            assert 'frozenset(["Cookie", "Authorization"])' in text
            assert 'frozenset([\\"Cookie\\", \\"Authorization\\"])' in text

    def test_response_templates_no_longer_suggest_quoted_string_wording(self):
        """The citation placeholder itself must not use wording that
        suggests the citation should be represented as a quoted string --
        only that it is exact, contiguous text with no surrounding
        delimiter."""
        for text in (self._analyze_text(), self._challenge_text()):
            assert "no surrounding delimiter" in text
            assert "a short verbatim quote from the repository evidence" not in text

    def test_prompts_forbid_confidence_scores(self):
        for text in (self._analyze_text(), self._challenge_text()):
            assert "confidence score" in text.lower()

    def test_verdict_vocabulary_is_exactly_three(self):
        assert VERDICTS == ("PROVEN", "REFUTED", "UNRESOLVED")

    def test_challenge_prompt_no_longer_references_a_prior_pass(self):
        """Item 13 -- Pass 2 Information Isolation: the prompt must no
        longer refer to "the first pass" at all, nor claim Pass 2 is
        shown a prior verdict/reasoning/citations, since none of that is
        rendered into its input anymore."""
        text = self._challenge_text().lower()
        assert "first pass" not in text
        assert "shown its verdict" not in text
        assert "prior pass" not in text

    def test_challenge_prompt_still_contains_the_sufficiency_defeater_framework(self):
        """Item 14 -- the underlying reasoning framework (identify
        supporting facts -> check joint sufficiency -> identify the
        required link -> search for a coexisting defeater -> only then
        finalize) must survive the subject-only rewrite intact. Loose,
        non-overfit substring checks on purpose."""
        text = self._challenge_text().lower()
        assert "supporting fact" in text
        assert "sufficient" in text
        assert "required link" in text
        assert "coexist" in text
        assert "finalize" in text

    def test_pass2_prioritizes_the_original_proposition_over_pass1s_argument(self):
        """Locks in the Run 1 semantic-completeness fix: Pass 2 must be
        told the original proposition, not Pass 1's candidate argument,
        is the thing being decided -- deliberately loose wording checks
        (not a verbatim match) so this doesn't become brittle to
        rephrasing that preserves the same substance."""
        text = self._challenge_text().lower()
        assert "original proposition" in text
        assert "candidate argument" in text

    def test_pass2_requires_a_coexisting_defeater_search(self):
        """The prompt must ask whether Pass 1's supporting facts are
        JOINTLY SUFFICIENT for the proposition, and require a search for
        evidence that could coexist with those facts (not merely
        contradict them) while still defeating the proposition -- this is
        the specific gap Run 1 Concern #2 fell through (every cited fact
        was true; nothing checked whether they were sufficient)."""
        text = self._challenge_text().lower()
        assert "sufficient" in text
        assert "coexist" in text
        assert "required link" in text

    def test_pass2_no_longer_frames_the_job_as_merely_finding_fault_with_pass1(self):
        """Negative check for the specific anchoring bug diagnosed in Run
        1: the job must not be framed solely as auditing whether Pass 1's
        own candidate could be wrong -- it must be framed around the
        original proposition instead (see the two tests above)."""
        text = self._challenge_text().lower()
        assert "find a reason the candidate could be wrong" not in text

    def test_output_contract_fields_unchanged(self):
        """The revision is prompt wording only -- no new/renamed output
        fields, no schema change."""
        text = self._challenge_text()
        assert "Challenge result:" in text
        assert "Final verdict:" in text
        assert "Final reasoning:" in text
        assert "Citations:" in text
        for forbidden_field in (
            "Necessary conditions:", "Proof obligations:", "Defeaters:",
            "Completeness:", "Confidence:",
        ):
            assert forbidden_field not in text


class TestBareCitationProtocol:
    """Regression tests for the Bare Citation Protocol -- citations are
    written directly after the bullet marker with no surrounding
    delimiter of any kind. Covers exactly the failure class observed on
    the real archived Run 1: a source line containing embedded quote
    characters, which the model must copy exactly rather than wrap and
    escape. Parser and validator code are entirely UNCHANGED -- every
    test here proves the existing, unmodified `_extract_bulleted_section`
    / `_point_citation_valid` already accept bare citations of every
    shape below; only the prompt wording changed."""

    @staticmethod
    def _bare_pass1(citation_line: str) -> str:
        return (
            f"Candidate verdict: PROVEN\nReasoning: r\nCitations:\n- {citation_line}\n"
            f"Missing evidence: none\n"
        )

    def test_bare_citation_with_double_quotes_parses_and_validates(self):
        evidence = 'foo = ["a", "b"]'
        action = parse_pass1(self._bare_pass1(evidence))
        assert action.kind == "PROVEN"
        assert action.citations == (evidence,)
        assert _point_citation_valid(evidence, evidence) is True

    def test_bare_citation_with_single_quotes_parses_and_validates(self):
        evidence = "foo = 'bar'"
        action = parse_pass1(self._bare_pass1(evidence))
        assert action.citations == (evidence,)
        assert _point_citation_valid(evidence, evidence) is True

    def test_bare_citation_with_backticks_parses_and_validates(self):
        evidence = "const message = `hello ${name}`;"
        action = parse_pass1(self._bare_pass1(evidence))
        assert action.citations == (evidence,)
        assert _point_citation_valid(evidence, evidence) is True

    def test_bare_citation_with_backslashes_parses_and_validates(self):
        evidence = 'path = "C:\\temp"'
        action = parse_pass1(self._bare_pass1(evidence))
        assert action.citations == (evidence,)
        assert _point_citation_valid(evidence, evidence) is True

    def test_bare_citation_with_both_quote_types_parses_and_validates(self):
        evidence = "print(\"it's fine\")"
        action = parse_pass1(self._bare_pass1(evidence))
        assert action.citations == (evidence,)
        assert _point_citation_valid(evidence, evidence) is True

    def test_genuinely_altered_citation_still_rejected(self):
        """Negative control -- the validator's strictness is unaffected
        by this protocol: a citation that does not match the evidence,
        bare or otherwise, still fails."""
        evidence = 'foo = ["a", "b"]'
        fabricated = 'foo = ["a", "c"]'
        assert _point_citation_valid(fabricated, evidence) is False

    def test_empty_citations_section_rejected_for_claimed_verdict(self):
        """Empty/whitespace-only citation coverage: a `Citations:` heading
        with zero bullets under it must still fail closed for a claimed
        PROVEN verdict -- unaffected by, and not previously covered
        against, this protocol change."""
        raw = "Candidate verdict: PROVEN\nReasoning: r\nCitations:\nMissing evidence: none\n"
        action = parse_pass1(raw)
        assert action.kind == "INVALID"

    def test_render_pass1_result_no_longer_wired_into_live_resolver_path(self):
        """Pass 2 Information Isolation experiment: `_render_pass1_result`
        is retained (still directly testable, e.g. for a future
        observability tool) but must not be called anywhere in the live
        `resolve_concern` control flow -- confirmed by source inspection,
        not merely behavioral absence, since a behavioral test alone
        could not distinguish "never called" from "called but its output
        happens not to appear elsewhere."."""
        import ast
        import inspect
        from utilities.autopatcher import simple_concern_resolver as scr

        def _code_without_docstring(func) -> str:
            src = inspect.getsource(func)
            tree = ast.parse(src)
            fn = tree.body[0]
            body = fn.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                lines = src.splitlines()
                return "\n".join(lines[body[0].end_lineno:])
            return src

        assert "_render_pass1_result" not in _code_without_docstring(scr._run_pass2)
        assert "_render_pass1_result" not in _code_without_docstring(scr.resolve_concern)

    def test_render_pass1_result_preserves_bare_citation_unchanged(self):
        """`_render_pass1_result` itself (still a standalone, directly
        testable helper -- see the isolation test above for confirmation
        it is no longer wired into the live Pass 2 call) must not
        introduce any delimiter/serialization layer of its own when
        rendering a bare citation."""
        evidence = 'foo = ["a", "b"]'
        pass1 = Pass1Result(kind="PROVEN", reasoning="r", citations=(evidence,))
        rendered = _render_pass1_result(pass1)
        assert f"- {evidence}" in rendered
        assert f'"{evidence}"' not in rendered
        assert f"`{evidence}`" not in rendered


class TestPass2InformationIsolation:
    """Regression tests for the Pass 2 Information Isolation experiment:
    Pass 2 must receive the original proposition and the same shared
    evidence pool Pass 1 saw (including anything Pass 1's acquisition
    round added to it), but none of Pass 1's own verdict, reasoning, or
    selected citations. Generic, non-urllib3 content throughout."""

    class _RecordingLLM:
        """Records every (system_prompt, user_message, stage) call and
        returns scripted responses in order -- lets a test inspect
        exactly what Pass 2 was rendered, distinct from a plain
        side_effect mock which discards the call arguments."""

        def __init__(self, *responses):
            self._responses = list(responses)
            self.calls = []

        def complete(self, system_prompt, user_message, stage=None, **_kwargs):
            self.calls.append({"system_prompt": system_prompt, "user_message": user_message, "stage": stage})
            return self._responses.pop(0)

    def _pass2_call(self, llm):
        return next(c for c in llm.calls if c["stage"] == "simple_concern_pass2")

    def test_pass1_still_executes(self):
        """Item 1."""
        llm = self._RecordingLLM(_pass1(citation="op()"), _pass2(citation="op()"))
        resolve_concern("x", code_context="op()", patch="", llm=llm)
        assert any(c["stage"] == "simple_concern_pass1" for c in llm.calls)

    def test_pass1_result_remains_stored_in_final_result(self):
        """Item 2."""
        llm = self._RecordingLLM(
            _pass1(citation="op()", reasoning="a distinctive pass1 rationale"), _pass2(citation="op()"),
        )
        result = resolve_concern("x", code_context="op()", patch="", llm=llm)
        assert result["pass1"]["kind"] == "PROVEN"
        assert result["pass1"]["reasoning"] == "a distinctive pass1 rationale"

    def test_pass2_input_contains_original_proposition(self):
        """Item 3."""
        llm = self._RecordingLLM(_pass1(citation="op()"), _pass2(citation="op()"))
        resolve_concern("a distinctive proposition string", code_context="op()", patch="", llm=llm)
        assert "a distinctive proposition string" in self._pass2_call(llm)["user_message"]

    def test_pass2_input_contains_raw_code_context(self):
        """Item 4."""
        llm = self._RecordingLLM(
            _pass1(citation="a_distinctive_evidence_token"), _pass2(citation="a_distinctive_evidence_token"),
        )
        resolve_concern("x", code_context="a_distinctive_evidence_token", patch="", llm=llm)
        assert "a_distinctive_evidence_token" in self._pass2_call(llm)["user_message"]

    def test_pass2_input_contains_patch(self):
        """Item 5."""
        llm = self._RecordingLLM(_pass1(citation="op()"), _pass2(citation="op()"))
        resolve_concern("x", code_context="op()", patch="a distinctive patch diff", llm=llm)
        assert "a distinctive patch diff" in self._pass2_call(llm)["user_message"]

    def test_pass2_input_contains_acquired_raw_evidence(self, tmp_path):
        """Item 6."""
        (tmp_path / "mod.py").write_text("a_distinctive_acquired_token\n")
        llm = self._RecordingLLM(
            _pass1_missing(file_hint="mod.py"),
            _pass1(citation="a_distinctive_acquired_token"),
            _pass2(citation="a_distinctive_acquired_token"),
        )
        resolve_concern(
            "x", code_context="", patch="", llm=llm, repo_root=tmp_path, investigation_context=object(),
        )
        assert "a_distinctive_acquired_token" in self._pass2_call(llm)["user_message"]

    def test_pass2_input_lacks_distinctive_pass1_verdict(self):
        """Item 7 -- Pass 1 REFUTED while Pass 2 answers PROVEN, so a
        leaked "Candidate verdict: REFUTED" string would be unambiguous."""
        llm = self._RecordingLLM(_pass1(verdict="REFUTED", citation="op()"), _pass2(verdict="PROVEN", citation="op()"))
        resolve_concern("x", code_context="op()", patch="", llm=llm)
        assert "Candidate verdict: REFUTED" not in self._pass2_call(llm)["user_message"]

    def test_pass2_input_lacks_distinctive_pass1_reasoning(self):
        """Item 8."""
        llm = self._RecordingLLM(
            _pass1(citation="op()", reasoning="a distinctive pass1 rationale sentence"), _pass2(citation="op()"),
        )
        resolve_concern("x", code_context="op()", patch="", llm=llm)
        assert "a distinctive pass1 rationale sentence" not in self._pass2_call(llm)["user_message"]

    def test_pass2_input_lacks_pass1_candidate_result_section(self):
        """Item 9."""
        llm = self._RecordingLLM(_pass1(citation="op()"), _pass2(citation="op()"))
        resolve_concern("x", code_context="op()", patch="", llm=llm)
        assert "## Pass 1 candidate result" not in self._pass2_call(llm)["user_message"]

    def test_pass1_selected_citations_not_separately_curated_for_pass2(self):
        """Item 10 -- the underlying citation TEXT may legitimately
        appear in Pass 2's input because it is part of the raw shared
        evidence; this asserts the absence of the CURATED Pass 1
        citation section/representation specifically, not absence of the
        text itself."""
        llm = self._RecordingLLM(_pass1(citation="op()"), _pass2(citation="op()"))
        resolve_concern("x", code_context="op()", patch="", llm=llm)
        user_message = self._pass2_call(llm)["user_message"]
        assert "op()" in user_message  # legitimately present as shared evidence
        assert "## Pass 1 candidate result" not in user_message
        assert "Candidate verdict:" not in user_message

    def test_final_reconciliation_still_uses_only_pass2(self):
        """Item 11 -- existing reconciliation tests elsewhere in this
        file (e.g. TestPass2CanChangeVerdict) already cover this and
        continue to pass unmodified; this test reconfirms it explicitly
        under the isolation change specifically."""
        llm = self._RecordingLLM(
            _pass1(verdict="PROVEN", citation="op()"),
            _pass2(verdict="REFUTED", citation="raise Err()"),
        )
        result = resolve_concern("x", code_context="op()\nraise Err()", patch="", llm=llm)
        assert result["final_verdict"] == "REFUTED"
