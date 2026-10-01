"""Regression tests: block-local guard/operation ordering, the trusted
`Post-patch definition` evidence block, and the self-contained
`Requires explicit non-default action` prompt contract.

Architectural pattern under test (repository-neutral): a patch inserts a
protective line (a value transformation, or a conditional check) before an
operation that the patch itself does not touch and that lies outside the
hunk's own context lines. The guard citation is then findable only in the
diff and the operation citation only in pre-patch repository evidence, so
no single evidence block contains both. The complete post-change function,
read from the isolated patched workspace and rendered as one trusted block,
is the only evidence in which their ordering is observable.

Ordering is only ever established inside ONE rendered block (a fenced
source block, a grounding excerpt, or one diff hunk) -- never by positions
in a concatenated corpus, never across blocks or sources.

Hermetic: no LLM (the Challenger's model is a MagicMock returning a fixed
response), no network.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest import mock

import pytest


# ---------------------------------------------------------------------------
# Generic fixtures
# ---------------------------------------------------------------------------

_PRE_SOURCE = (
    "def handle(payload, sink, strict=True):\n"
    "    data = payload.get(\"body\")\n"
    "    data = data or \"\"\n"
    "    size = len(data)\n"
    "    if size > 10:\n"
    "        size = 10\n"
    "    label = \"item\"\n"
    "    label = label.upper()\n"
    "    sink.write(data)\n"
    "    return size"
)

_TRANSFORM_LINE = "data = scrub(data)"
_CHECK_LINE = "if strict and not trusted(data): return 0"
_OPERATION_LINE = "sink.write(data)"
_DEFAULT_DECL = "strict=True"


def _post_source(inserted: str) -> str:
    lines = _PRE_SOURCE.splitlines()
    lines.insert(2, "    " + inserted)
    return "\n".join(lines)


def _block(heading: str, label: str, source: str, start: int = 1) -> str:
    end = start + len(source.splitlines()) - 1
    return f"#### {heading}: `pkg/handler.py:{label}` (lines {start}–{end})\n\n```python\n{source}\n```\n"


_PRE_BLOCK = _block("Target definition", "handle", _PRE_SOURCE)
_PRE_WINDOW = (
    "#### Discovered consumer: `pkg/handler.py:handle` (lines 1–10, deterministic discovered usage)\n\n"
    f"```python\n{_PRE_SOURCE}\n```\n"
)
_PRE_VERIFIED = (
    "#### Verified source: `pkg/handler.py:handle` (lines 1–10)\n\n"
    f"```python\n{_PRE_SOURCE}\n```\n"
)


def _post_block(inserted: str = _TRANSFORM_LINE) -> str:
    return _block("Post-patch definition", "handle", _post_source(inserted))


def _patch(inserted: str = _TRANSFORM_LINE) -> str:
    """One hunk inserting `inserted`; trailing context stops before the
    operation, which is therefore NOT present anywhere in the diff."""
    return (
        "```diff\n"
        "--- a/pkg/handler.py\n"
        "+++ b/pkg/handler.py\n"
        "@@ -1,5 +1,6 @@\n"
        " def handle(payload, sink, strict=True):\n"
        "     data = payload.get(\"body\")\n"
        f"+    {inserted}\n"
        "     data = data or \"\"\n"
        "     size = len(data)\n"
        "     if size > 10:\n"
        "```"
    )


def _concern(
    *, guard_prov=_TRANSFORM_LINE, op_prov=_OPERATION_LINE,
    default_state="condition_true_under_default", default_state_prov=_TRANSFORM_LINE,
    effect="neutralizes_operation", effect_prov=_TRANSFORM_LINE,
    override="false", override_prov="none",
) -> str:
    return (
        "1. Role: primary\n"
        "   Description: Whether unsanitized input still reaches the write.\n"
        "   Operation present in evidence: present\n"
        "   Preceding guard: present\n"
        f"   Guard provenance: {guard_prov}\n"
        "   Function provenance: none\n"
        f"   Operation provenance: {op_prov}\n"
        f"   Guard default state: {default_state}\n"
        f"   Guard default state provenance: {default_state_prov}\n"
        f"   Guard effect: {effect}\n"
        f"   Guard effect provenance: {effect_prov}\n"
        "   Reentry state propagation: not_applicable\n"
        "   Reentry provenance: none\n"
        f"   Requires explicit non-default action: {override}\n"
        f"   Override provenance: {override_prov}\n"
        "   Contract addresses override: not_applicable\n"
        "   Scope provenance: none\n"
    )


def _check_concern(**kw) -> str:
    base = dict(
        guard_prov=_CHECK_LINE, default_state_prov=_DEFAULT_DECL,
        effect="prevents_operation", effect_prov="return 0",
    )
    base.update(kw)
    return _concern(**base)


def _response(concern: str) -> str:
    return (
        "Verification status: VERIFIED_FIXED\n\n"
        f"Concerns:\n\n{concern}\n"
        "Edge cases:\n- none\n\nPotential issues:\n- none\n\nSummary:\n- none\n"
    )


def _challenge(concern: str, *, corpus: str, patch: str, shown: "str | None" = None) -> dict:
    from utilities.autopatcher.patch_challenger import challenge_patch

    llm = mock.MagicMock()
    llm.complete.return_value = _response(concern)
    return challenge_patch(
        "Untrusted input reaches a write.", patch, llm,
        code_context=(corpus if shown is None else shown), provenance_context=corpus,
    )


def _facts(result: dict) -> dict:
    return result["concerns"][0]["reachability_facts"]


_REPORTED_TRANSFORM_FACTS = {
    "operation_present_in_evidence": "present",
    "preceding_guard": "present",
    "guard_default_state": "condition_true_under_default",
    "guard_effect": "neutralizes_operation",
    "reentry_state_propagation": "not_applicable",
}


# ---------------------------------------------------------------------------
# Block-local ordering (parser)
# ---------------------------------------------------------------------------

class TestPostChangeDefinitionEstablishesOrdering:
    def test_1_transformation_in_patch_operation_outside_hunk_post_definition_orders_them(self):
        """Case 1: the transformation exists only as a diff line, the
        operation only in pre-change evidence outside the hunk, and the
        complete post-change definition (rendered AFTER the pre-change
        copy, as the pipeline orders them) contains both, in order."""
        result = _challenge(_concern(), corpus=_PRE_BLOCK + "\n\n" + _post_block(), patch=_patch())
        assert _facts(result)["preceding_guard"] == "present"
        assert result["concerns"][0]["default_execution_reachability"] == "blocked"
        assert result["concerns"][0]["consequence"] == "NON_BLOCKING"
        assert result["verification_status"] == "VERIFIED_FIXED"

    def test_2_both_citations_in_same_trusted_post_change_block(self):
        result = _challenge(_concern(), corpus=_post_block(), patch="")
        assert _facts(result)["preceding_guard"] == "present"

    def test_3_reversed_order_inside_same_block_does_not_establish_order(self):
        lines = _PRE_SOURCE.splitlines()
        lines.insert(len(lines) - 1, "    " + _TRANSFORM_LINE)  # after the operation
        reversed_block = _block("Post-patch definition", "handle", "\n".join(lines))
        result = _challenge(_concern(), corpus=reversed_block, patch="")
        assert _facts(result)["preceding_guard"] == "unresolved"
        assert result["concerns"][0]["consequence"] == "UNRESOLVED"

    def test_4_guard_and_operation_in_different_trusted_blocks_do_not_establish_order(self):
        """Each citation is individually grounded, and the guard's block
        is textually earlier in the corpus -- but no ONE block contains
        both, so global position must not establish order."""
        first = (
            "#### Target definition: `pkg/alpha.py:first` (lines 1–2)\n\n"
            f"```python\ndef first(data):\n    {_TRANSFORM_LINE}\n```\n"
        )
        second = (
            "#### Target definition: `pkg/beta.py:second` (lines 1–2)\n\n"
            f"```python\ndef second(sink, data):\n    {_OPERATION_LINE}\n```\n"
        )
        result = _challenge(_concern(), corpus=first + "\n\n" + second, patch="")
        assert _facts(result)["preceding_guard"] == "unresolved"

    def test_4b_guard_and_operation_in_different_diff_hunks_do_not_establish_order(self):
        patch = (
            "```diff\n--- a/pkg/handler.py\n+++ b/pkg/handler.py\n"
            "@@ -1,2 +1,3 @@\n def handle(payload, sink, strict=True):\n"
            f"+    {_TRANSFORM_LINE}\n     data = payload.get(\"body\")\n"
            "@@ -8,2 +9,2 @@\n     label = label.upper()\n"
            f"-    {_OPERATION_LINE}\n+    {_OPERATION_LINE}  # changed\n"
            "```"
        )
        result = _challenge(_concern(), corpus="", patch=patch)
        assert _facts(result)["preceding_guard"] == "unresolved"

    def test_4c_guard_and_operation_in_same_diff_hunk_still_order(self):
        """Legacy shape preserved: a hunk that itself contains both the
        inserted line and the later operation is one block."""
        patch = (
            "```diff\n--- a/pkg/handler.py\n+++ b/pkg/handler.py\n"
            "@@ -1,3 +1,4 @@\n def handle(payload, sink, strict=True):\n"
            f"+    {_TRANSFORM_LINE}\n     data = payload.get(\"body\")\n     {_OPERATION_LINE}\n"
            "```"
        )
        result = _challenge(_concern(), corpus="", patch=patch)
        assert _facts(result)["preceding_guard"] == "present"

    def test_5_duplicate_pre_change_copies_do_not_override_block_local_order(self):
        """Several pre-change copies of the operation (different renderers)
        precede the post-change block; first-match over the concatenation
        would compare against the WRONG copy."""
        corpus = "\n\n".join([_PRE_VERIFIED, _PRE_BLOCK, _PRE_WINDOW, _post_block()])
        result = _challenge(_concern(), corpus=corpus, patch=_patch())
        assert _facts(result)["preceding_guard"] == "present"

    def test_5c_reversed_copy_in_an_earlier_block_does_not_defeat_correct_block(self):
        """An unrelated earlier block contains both lines in the opposite
        order; neither its position nor its order may decide for the
        post-change block, whose own order is correct."""
        unrelated = (
            "#### Related definition (context only, not an approved edit target): "
            "`pkg/other.py:replay` (lines 1–3)\n\n"
            f"```python\ndef replay(sink, data):\n    {_OPERATION_LINE}\n    {_TRANSFORM_LINE}\n```\n"
        )
        corpus = "\n\n".join([unrelated, _PRE_BLOCK, _post_block()])
        result = _challenge(_concern(), corpus=corpus, patch=_patch())
        assert _facts(result)["preceding_guard"] == "present"

    def test_5b_operation_before_and_after_guard_in_same_block_does_not_order(self):
        """Within one block the guard must precede the operation's FIRST
        occurrence -- a later guarded copy cannot vouch for an earlier
        unguarded one."""
        lines = _post_source(_TRANSFORM_LINE).splitlines()
        lines.insert(1, "    " + _OPERATION_LINE)
        block = _block("Post-patch definition", "handle", "\n".join(lines))
        result = _challenge(_concern(), corpus=block, patch="")
        assert _facts(result)["preceding_guard"] == "unresolved"

    def test_6_post_change_block_shown_but_outside_authoritative_corpus_is_rejected(self):
        """Shown to the model but NOT in the citation-authority corpus:
        the guard is then only citable in the diff, the operation only in
        the pre-change block -- no shared block, so unresolved."""
        shown = _PRE_BLOCK + "\n\n" + _post_block()
        result = _challenge(_concern(), corpus=_PRE_BLOCK, patch=_patch(), shown=shown)
        assert _facts(result)["preceding_guard"] == "unresolved"

    def test_6b_fabricated_guard_citation_is_rejected(self):
        result = _challenge(
            _concern(guard_prov="data = totally_safe(data)"),
            corpus=_PRE_BLOCK + "\n\n" + _post_block(), patch=_patch(),
        )
        assert _facts(result)["preceding_guard"] == "unresolved"

    def test_7_missing_post_change_definition_remains_unresolved(self):
        result = _challenge(_concern(), corpus=_PRE_BLOCK, patch=_patch())
        assert _facts(result)["preceding_guard"] == "unresolved"
        assert result["verification_status"] == "INSUFFICIENT_EVIDENCE"

    def test_8_malformed_post_change_block_remains_unresolved(self):
        """A heading whose fenced source never closes is not a block."""
        truncated = (
            "#### Post-patch definition: `pkg/handler.py:handle` (lines 1–11)\n\n"
            "```python\n" + _post_source(_TRANSFORM_LINE) + "\n"
        )
        result = _challenge(_concern(), corpus=_PRE_BLOCK + "\n\n" + truncated, patch=_patch())
        assert _facts(result)["preceding_guard"] == "unresolved"

    def test_9_conditional_check_case_still_works(self):
        result = _challenge(
            _check_concern(), corpus=_PRE_BLOCK + "\n\n" + _post_block(_CHECK_LINE), patch=_patch(_CHECK_LINE),
        )
        assert _facts(result) == {
            "operation_present_in_evidence": "present",
            "preceding_guard": "present",
            "guard_default_state": "condition_true_under_default",
            "guard_effect": "prevents_operation",
            "reentry_state_propagation": "not_applicable",
        }
        assert result["concerns"][0]["consequence"] == "NON_BLOCKING"

    def test_10_always_executed_transformation_retains_reported_facts(self):
        result = _challenge(_concern(), corpus=_PRE_BLOCK + "\n\n" + _post_block(), patch=_patch())
        assert _facts(result) == _REPORTED_TRANSFORM_FACTS


class TestOrderingUnitsPreserveLegacyShapes:
    def test_unstructured_single_source_is_one_block(self):
        """A plain evidence string with no rendered-block structure at all
        (legacy direct callers) is itself one block."""
        source = f"def handle(data, sink):\n    {_TRANSFORM_LINE}\n    {_OPERATION_LINE}\n"
        result = _challenge(_concern(), corpus=source, patch="")
        assert _facts(result)["preceding_guard"] == "present"

    def test_grounding_excerpt_is_one_block(self):
        corpus = f"# pkg/handler.py (lines 1-3)\ndef handle(data, sink):\n    {_TRANSFORM_LINE}\n    {_OPERATION_LINE}\n"
        result = _challenge(_concern(), corpus=corpus, patch="")
        assert _facts(result)["preceding_guard"] == "present"

    def test_two_grounding_excerpts_are_two_blocks(self):
        corpus = (
            f"# pkg/alpha.py (lines 1-2)\ndef first(data):\n    {_TRANSFORM_LINE}\n\n"
            f"# pkg/beta.py (lines 1-2)\ndef second(sink, data):\n    {_OPERATION_LINE}\n"
        )
        result = _challenge(_concern(), corpus=corpus, patch="")
        assert _facts(result)["preceding_guard"] == "unresolved"

    def test_prose_outside_rendered_blocks_cannot_establish_order(self):
        corpus = (
            f"## Notes\n\nThe code calls `{_TRANSFORM_LINE}` and then `{_OPERATION_LINE}`.\n\n"
            + _PRE_BLOCK
        )
        result = _challenge(_concern(), corpus=corpus, patch="")
        assert _facts(result)["preceding_guard"] == "unresolved"


# ---------------------------------------------------------------------------
# Override-field contract (prompt + unchanged deterministic handling)
# ---------------------------------------------------------------------------

def _override_bullet() -> str:
    from utilities.autopatcher.patch_challenger import _PROMPT_PATH

    text = _PROMPT_PATH.read_text(encoding="utf-8")
    start = text.index("- `Requires explicit non-default action`:")
    end = text.index("- `Contract addresses override`:", start)
    return text[start:end]


class TestOverrideFieldContract:
    def test_11_applicability_is_stated_in_terms_of_reported_atomic_facts(self):
        bullet = _override_bullet()
        assert "`Guard effect`" in bullet
        assert "`prevents_operation`" in bullet and "`neutralizes_operation`" in bullet
        # never in terms of the derived label the model is told not to compute
        normalized = " ".join(bullet.split())
        assert "reachability is `blocked`" not in normalized
        assert "reachability IS `blocked`" not in normalized
        assert "`blocked`" not in normalized
        for value in ("`true`", "`false`", "`unresolved`", "`not_applicable`"):
            assert value in bullet

    def test_11b_answer_from_facts_alone_resolves_deterministically(self):
        """`false`, answered from the reported guard facts with no derived
        label, yields NON_BLOCKING through the UNCHANGED policy."""
        result = _challenge(_concern(override="false"), corpus=_post_block(), patch="")
        assert result["concerns"][0]["requires_explicit_non_default_action"] == "false"
        assert result["concerns"][0]["consequence"] == "NON_BLOCKING"

    def test_12_genuinely_insufficient_override_information_remains_unresolved(self):
        result = _challenge(_concern(override="unresolved"), corpus=_post_block(), patch="")
        assert result["concerns"][0]["consequence"] == "UNRESOLVED"
        assert result["verification_status"] == "INSUFFICIENT_EVIDENCE"

    def test_12b_not_applicable_under_protective_guard_still_fails_closed(self):
        """Deterministic handling is unchanged: the old ambiguous answer
        is still demoted to unresolved, never reinterpreted as `false`."""
        result = _challenge(_concern(override="not_applicable"), corpus=_post_block(), patch="")
        assert result["concerns"][0]["requires_explicit_non_default_action"] == "unresolved"
        assert result["concerns"][0]["consequence"] == "UNRESOLVED"

    def test_12c_true_without_grounded_override_provenance_is_unresolved(self):
        result = _challenge(
            _concern(override="true", override_prov="handle(payload, sink, strict=False)"),
            corpus=_post_block(), patch="",
        )
        assert result["concerns"][0]["requires_explicit_non_default_action"] == "unresolved"
        assert result["concerns"][0]["consequence"] == "UNRESOLVED"


# ---------------------------------------------------------------------------
# Renderer: complete post-change definition from the patched workspace index
# ---------------------------------------------------------------------------

def _observation(func_id="pkg/handler.py:handle", status="changed", kind="resolved_function"):
    from utilities.autopatcher.post_patch_evaluation import AnchorObservation
    from utilities.autopatcher.post_patch_investigation import ResolvedFunctionKey, ResolvedFunctionValue

    return AnchorObservation(
        anchor_kind=kind,
        anchor_key=ResolvedFunctionKey(func_id=func_id, name="handle", class_name=None, unit_type="function"),
        candidate_path="pkg/handler.py", status=status,
        before_value=ResolvedFunctionValue(1, 10), after_value=ResolvedFunctionValue(1, 11),
        details=None, source="test", evaluated_via="test", origin="patch_touched",
    )


class _Index:
    def __init__(self, functions):
        self.functions = functions

    def get_function(self, func_id):
        return self.functions.get(func_id)

    def get_function_code(self, func_id):
        f = self.functions.get(func_id)
        return f.get("code") if f else None

    def read_file_section(self, file_path, start_line, end_line):
        """Patched-copy file content, modeled as each function's own source
        laid out from its startLine (mirrors RepositoryIndex's clamp-at-EOF
        slicing); no source for a file -> None."""
        for func_id, f in self.functions.items():
            if func_id.rsplit(":", 1)[0] == file_path and isinstance(f.get("code"), str):
                lines = [""] * ((f.get("startLine") or 1) - 1) + f["code"].splitlines(keepends=True)
                return "".join(lines[max(0, start_line - 1):min(len(lines), end_line)])
        return None


def _context(functions):
    return mock.MagicMock(index=_Index(functions))


_GOOD_FUNCTION = {"startLine": 1, "endLine": 11, "code": _post_source(_TRANSFORM_LINE)}


class TestRenderPostPatchDefinitions:
    def _render(self, observations, context, max_chars=100_000):
        from utilities.autopatcher.post_patch_evaluation import render_post_patch_definitions
        return render_post_patch_definitions(observations, context, max_chars=max_chars)

    def test_renders_changed_function_as_trusted_post_patch_definition_block(self):
        rendered = self._render([_observation()], _context({"pkg/handler.py:handle": _GOOD_FUNCTION}))
        assert _post_block() in rendered

    def test_rendered_block_is_accepted_by_block_local_ordering(self):
        rendered = self._render([_observation()], _context({"pkg/handler.py:handle": _GOOD_FUNCTION}))
        result = _challenge(_concern(), corpus=_PRE_BLOCK + "\n\n" + rendered, patch=_patch())
        assert _facts(result) == _REPORTED_TRANSFORM_FACTS

    @pytest.mark.parametrize("observation", [
        _observation(status="unchanged"),
        _observation(status="disappeared"),
        _observation(status="evaluation_error"),
    ])
    def test_only_changed_functions_are_rendered(self, observation):
        assert self._render([observation], _context({"pkg/handler.py:handle": _GOOD_FUNCTION})) == ""

    @pytest.mark.parametrize("context", [
        None,
        mock.MagicMock(index=None),
        _context({}),
        _context({"pkg/handler.py:handle": {"startLine": 1, "endLine": 11, "code": None}}),
        _context({"pkg/handler.py:handle": {"startLine": 1, "endLine": 11, "code": "   \n"}}),
        _context({"pkg/handler.py:handle": {"startLine": None, "endLine": 11, "code": _GOOD_FUNCTION["code"]}}),
        # header would claim lines the source does not contain
        _context({"pkg/handler.py:handle": {"startLine": 1, "endLine": 40, "code": _GOOD_FUNCTION["code"]}}),
    ])
    def test_8_missing_or_malformed_source_renders_nothing(self, context):
        assert self._render([_observation()], context) == ""

    def test_index_failure_renders_nothing(self):
        index = mock.MagicMock()
        index.get_function.side_effect = RuntimeError("boom")
        assert self._render([_observation()], mock.MagicMock(index=index)) == ""

    def test_block_that_does_not_fit_capacity_is_omitted_whole(self):
        rendered = self._render(
            [_observation()], _context({"pkg/handler.py:handle": _GOOD_FUNCTION}), max_chars=50,
        )
        assert rendered == ""

    def test_duplicate_observations_render_one_block(self):
        rendered = self._render(
            [_observation(), _observation()], _context({"pkg/handler.py:handle": _GOOD_FUNCTION}),
        )
        assert rendered.count("#### Post-patch definition:") == 1


# ---------------------------------------------------------------------------
# Pipeline seam: patched workspace -> rendered block -> shown context AND
# authoritative corpus, byte-identical
# ---------------------------------------------------------------------------

_HANDLER_SOURCE = (
    "def handle(payload, sink, strict=True):\n"
    "    data = payload.get(\"body\")\n"
    "    data = data or \"\"\n"
    "    size = len(data)\n"
    "    if size > 10:\n"
    "        size = 10\n"
    "    label = \"item\"\n"
    "    label = label.upper()\n"
    "    sink.write(data)\n"
    "    return size\n"
)

_REAL_PATCH = (
    "```diff\n"
    "--- a/app/handler.py\n"
    "+++ b/app/handler.py\n"
    "@@ -1,5 +1,6 @@\n"
    " def handle(payload, sink, strict=True):\n"
    "     data = payload.get(\"body\")\n"
    f"+    {_TRANSFORM_LINE}\n"
    "     data = data or \"\"\n"
    "     size = len(data)\n"
    "     if size > 10:\n"
    "```"
)


def _write_repo(root: Path) -> None:
    auth = root / "app" / "auth.py"
    auth.parent.mkdir(parents=True)
    auth.write_text(
        "import sqlite3\n\n"
        "db = sqlite3.connect(\"users.db\")\n\n"
        "def authenticate(username, password):\n"
        "    query = f\"SELECT * FROM users WHERE username='{username}'\"\n"
        "    return db.execute(query).fetchone() is not None\n",
        encoding="utf-8",
    )
    (root / "app" / "handler.py").write_text(_HANDLER_SOURCE, encoding="utf-8")
    for cmd in (
        ["git", "init"], ["git", "config", "user.email", "t@t.com"], ["git", "config", "user.name", "T"],
        ["git", "add", "-A"], ["git", "commit", "-m", "init"],
    ):
        subprocess.run(cmd, cwd=root, capture_output=True)


class TestPipelineRendersPostPatchDefinition:
    def test_1_patched_workspace_definition_reaches_context_and_corpus_identically(self, tmp_path):
        from tests.patch.test_pipeline_post_patch_investigation import _CHALLENGER_CLEAN, _run_pipeline

        repo_root = tmp_path / "repo"
        _write_repo(repo_root)
        _, _, calls, mocks = _run_pipeline(
            tmp_path, patches_gen=[_REAL_PATCH], patches_chall=[_CHALLENGER_CLEAN], repo_root=str(repo_root),
        )
        challenge_mock = next(m for m in mocks if getattr(m, "_mock_name", None) == "challenge_patch")
        kwargs = challenge_mock.call_args.kwargs
        shown, corpus = kwargs["code_context"], kwargs["provenance_context"]

        expected_source = _HANDLER_SOURCE.rstrip().splitlines()
        expected_source.insert(2, "    " + _TRANSFORM_LINE)
        expected_block = (
            "#### Post-patch definition: `app/handler.py:handle` (lines 1–11)\n\n"
            "```python\n" + "\n".join(expected_source) + "\n```\n"
        )
        assert expected_block in shown
        assert expected_block in corpus

        # The real parser, fed exactly what production fed the Challenger,
        # keeps the model-reported transformation facts.
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = _response(_concern())
        result = challenge_patch(
            "Untrusted input reaches a write.", _REAL_PATCH, llm, code_context=shown, provenance_context=corpus,
        )
        assert _facts(result) == _REPORTED_TRANSFORM_FACTS
