"""Tests for Slice 4 -- Post-Patch Target Conformance and Recovery.

Covers check_patch_target_conformance, recover_post_patch_source,
build_post_patch_recovery_hint, and the pipeline.py wiring that ties them
together between Patch Generation and the existing applicability check.
"""

from __future__ import annotations

import json
from unittest import mock

import pytest

from utilities.autopatcher.remediation_planner import build_recovery_targets


def _make_context(functions=None, constants=None, repo_path=None):
    from utilities.agentic_enhancer.reachability_analyzer import ReachabilityAnalyzer
    from utilities.agentic_enhancer.repository_index import RepositoryIndex
    from utilities.autopatcher.candidate_enrichment import InvestigationContext

    functions = functions or {}
    index = RepositoryIndex({"functions": functions}, repo_path=str(repo_path) if repo_path else None)
    reachability = ReachabilityAnalyzer(functions, {}, set())
    return InvestigationContext(
        index=index, call_graph={}, reverse_call_graph={},
        reachability=reachability, constants=constants or {},
    )


def _make_strategy(target_files=None, target_symbols=None, extended_mechanism=None, required_edits=None):
    from utilities.autopatcher.remediation_planner import RemediationStrategyResult
    return RemediationStrategyResult(
        rendered="", target_files=target_files or [], target_symbols=target_symbols or [],
        warnings=[], extended_mechanism=extended_mechanism, required_edits=required_edits or [],
    )


def _make_slice_result(**overrides):
    from utilities.autopatcher.remediation_planner import FinalTargetSliceResult
    base = dict(
        rendered="", covered_target_files=[], covered_target_symbols=[],
        uncovered_target_files=[], uncovered_target_symbols=[],
        coverage_complete=False, has_any_coverage=False, warning_text="",
        resolved_target_symbols=[], full_file_fallback_covered=[],
        edit_target_budget_exhausted=False,
        resolved_symbol_files={}, identifier_definition_covered=[],
    )
    base.update(overrides)
    return FinalTargetSliceResult(**base)


def _make_ready_edit(file, symbol=None):
    from utilities.autopatcher.remediation_planner import IntendedEdit, ReadyEdit
    edit = IntendedEdit(file=file, symbol=symbol)
    return ReadyEdit(edit=edit, role="edit_target", file=file, symbol=symbol)


# ---------------------------------------------------------------------------
# check_patch_target_conformance
# ---------------------------------------------------------------------------

class TestPatchTargetConformance:
    def test_approved_and_verified_patch_is_fully_conformant(self, tmp_path):
        """Test 1 + Test 5: a patch whose only hunk exactly matches
        verified source for a ready edit is fully conformant, and no
        recovery trigger reason fires (unique_match)."""
        from utilities.autopatcher.diff_hunk_repair import repair_hunk_headers
        from utilities.autopatcher.remediation_planner import (
            build_final_target_slice, check_patch_target_conformance,
            post_patch_recovery_trigger_reasons,
        )

        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A"])
        slice_result = build_final_target_slice(strategy, str(tmp_path), context)
        ready_edits = [_make_ready_edit("mod.py", "mod.py:CONST_A")]

        patch = (
            "--- a/mod.py\n+++ b/mod.py\n@@ -1,1 +1,1 @@\n-CONST_A = 1\n+CONST_A = 2\n"
        )
        patch, meta = repair_hunk_headers(patch, repo_root=tmp_path)

        report = check_patch_target_conformance(patch, meta.relocations, ready_edits, slice_result)
        assert report.all_conformant is True
        assert report.results[0].target_coverage == "approved_target"
        assert report.results[0].old_side_status == "old_side_verified"
        assert post_patch_recovery_trigger_reasons(report) == []

    def test_unexpected_file_triggers_conformance_failure(self, tmp_path):
        """Test 2."""
        from utilities.autopatcher.diff_hunk_repair import repair_hunk_headers
        from utilities.autopatcher.remediation_planner import (
            check_patch_target_conformance, post_patch_recovery_trigger_reasons,
        )

        (tmp_path / "other.py").write_text("X = 1\n", encoding="utf-8")
        ready_edits = [_make_ready_edit("mod.py", "mod.py:CONST_A")]
        slice_result = _make_slice_result()

        patch = "--- a/other.py\n+++ b/other.py\n@@ -1,1 +1,1 @@\n-X = 1\n+X = 2\n"
        patch, meta = repair_hunk_headers(patch, repo_root=tmp_path)

        report = check_patch_target_conformance(patch, meta.relocations, ready_edits, slice_result)
        assert report.all_conformant is False
        assert report.unexpected_files == ["other.py"]
        assert "unexpected_file" in post_patch_recovery_trigger_reasons(report)

    def test_same_file_unrelated_source_does_not_satisfy_conformance(self, tmp_path):
        """Test 3: the ready edit's own file is touched, but the actual
        hunk edits a DIFFERENT part of it, not present in the verified
        (rendered) edit-target block -- must not be "approved_target"."""
        from utilities.autopatcher.diff_hunk_repair import repair_hunk_headers
        from utilities.autopatcher.remediation_planner import (
            build_final_target_slice, check_patch_target_conformance,
            post_patch_recovery_trigger_reasons,
        )

        # A large enough file that _DEFINITION_CONTEXT_LINES padding
        # around CONST_A (line 1) does not reach OTHER_LINE (line 11) --
        # otherwise the rendered capsule would incidentally include
        # OTHER_LINE as mere padding, defeating the point of this test.
        lines = ["CONST_A = 1\n"] + [f"filler_{i} = {i}\n" for i in range(1, 9)] + ["OTHER_LINE = 5\n"]
        (tmp_path / "mod.py").write_text("".join(lines), encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A"])
        slice_result = build_final_target_slice(strategy, str(tmp_path), context)
        ready_edits = [_make_ready_edit("mod.py", "mod.py:CONST_A")]

        # Edits OTHER_LINE, not CONST_A -- OTHER_LINE was never rendered
        # as edit-target source for this ready edit.
        patch = "--- a/mod.py\n+++ b/mod.py\n@@ -10,1 +10,1 @@\n-OTHER_LINE = 5\n+OTHER_LINE = 6\n"
        patch, meta = repair_hunk_headers(patch, repo_root=tmp_path)

        report = check_patch_target_conformance(patch, meta.relocations, ready_edits, slice_result)
        assert report.results[0].target_coverage == "uncovered_target"
        assert report.all_conformant is False
        assert "uncovered_target" in post_patch_recovery_trigger_reasons(report)

    def test_no_match_triggers_recovery(self, tmp_path):
        """Test 4."""
        from utilities.autopatcher.diff_hunk_repair import repair_hunk_headers
        from utilities.autopatcher.remediation_planner import (
            build_final_target_slice, check_patch_target_conformance,
            post_patch_recovery_trigger_reasons,
        )

        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A"])
        slice_result = build_final_target_slice(strategy, str(tmp_path), context)
        ready_edits = [_make_ready_edit("mod.py", "mod.py:CONST_A")]

        # Old-side text that does not exist anywhere in the real file.
        patch = "--- a/mod.py\n+++ b/mod.py\n@@ -1,1 +1,1 @@\n-THIS_NEVER_EXISTED = 99\n+CONST_A = 2\n"
        patch, meta = repair_hunk_headers(patch, repo_root=tmp_path)

        report = check_patch_target_conformance(patch, meta.relocations, ready_edits, slice_result)
        assert report.results[0].old_side_status == "old_side_no_match"
        assert "old_side_no_match" in post_patch_recovery_trigger_reasons(report)

    def test_ambiguous_old_side_alone_does_not_trigger_recovery(self, tmp_path):
        """Test 6: an approved target whose old-side matches the real
        file in more than one place is "old_side_ambiguous" (not fully
        conformant) but must NOT, by itself, trigger recovery. The
        rendered capsule for the ready symbol itself contains only ONE
        occurrence (so target_coverage is cleanly "approved_target");
        only the REAL file (searched by repair_hunk_headers for old-side
        verification) has a second, far-away duplicate."""
        from utilities.autopatcher.diff_hunk_repair import repair_hunk_headers
        from utilities.autopatcher.remediation_planner import (
            build_final_target_slice, check_patch_target_conformance,
            post_patch_recovery_trigger_reasons,
        )

        lines = ["CONST_A = 1\n"] + [f"filler_{i} = {i}\n" for i in range(1, 9)] + ["CONST_A = 1\n"]
        (tmp_path / "mod.py").write_text("".join(lines), encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A"])
        slice_result = build_final_target_slice(strategy, str(tmp_path), context)
        ready_edits = [_make_ready_edit("mod.py", "mod.py:CONST_A")]

        patch = "--- a/mod.py\n+++ b/mod.py\n@@ -1,1 +1,1 @@\n-CONST_A = 1\n+CONST_A = 2\n"
        patch, meta = repair_hunk_headers(patch, repo_root=tmp_path)

        report = check_patch_target_conformance(patch, meta.relocations, ready_edits, slice_result)
        assert report.results[0].old_side_status == "old_side_ambiguous"
        assert report.all_conformant is False
        # Ambiguity alone is never a trigger reason.
        assert post_patch_recovery_trigger_reasons(report) == []

    def test_wrong_header_line_number_is_ignored_content_is_the_anchor(self, tmp_path):
        """Test 7 + Test 8: a hunk header claiming the wrong line number,
        with old-side content that DOES exist (uniquely) in the real
        file, is still correctly verified via content, never via the
        claimed line."""
        from utilities.autopatcher.diff_hunk_repair import repair_hunk_headers
        from utilities.autopatcher.remediation_planner import (
            build_final_target_slice, check_patch_target_conformance,
        )

        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A"])
        slice_result = build_final_target_slice(strategy, str(tmp_path), context)
        ready_edits = [_make_ready_edit("mod.py", "mod.py:CONST_A")]

        # Claims line 99 -- wrong; content is real and unique.
        patch = "--- a/mod.py\n+++ b/mod.py\n@@ -99,1 +99,1 @@\n-CONST_A = 1\n+CONST_A = 2\n"
        patch, meta = repair_hunk_headers(patch, repo_root=tmp_path)

        assert meta.relocations[0].relocation_reason == "unique_match"
        assert meta.relocations[0].original_hunk_start == 99  # the LLM's untrusted claim
        assert meta.relocations[0].relocated_hunk_start == 1  # the real, content-verified location

        report = check_patch_target_conformance(patch, meta.relocations, ready_edits, slice_result)
        assert report.all_conformant is True

    def test_pure_new_file_patch_is_not_classified_as_no_match(self, tmp_path):
        """Test 12."""
        from utilities.autopatcher.diff_hunk_repair import repair_hunk_headers
        from utilities.autopatcher.remediation_planner import check_patch_target_conformance

        ready_edits = [_make_ready_edit("new_mod.py", None)]
        slice_result = _make_slice_result()

        patch = "--- /dev/null\n+++ b/new_mod.py\n@@ -0,0 +1,2 @@\n+NEW_CONST = 1\n+OTHER = 2\n"
        patch, meta = repair_hunk_headers(patch, repo_root=tmp_path)

        report = check_patch_target_conformance(patch, meta.relocations, ready_edits, slice_result)
        assert report.results[0].old_side_status == "new_file"
        assert report.results[0].old_side_status != "old_side_no_match"
        assert report.results[0].target_coverage == "approved_target"
        assert report.all_conformant is True


# ---------------------------------------------------------------------------
# Regression coverage for the wide-diff-context / narrow-rendered-capsule
# mismatch: a hunk whose own context is wider than _DEFINITION_CONTEXT_LINES
# can be genuinely old_side_verified (unique match against the real file)
# yet still miss the verbatim text search against the narrower rendered
# capsule. check_patch_target_conformance's position-based fallback (see
# its own docstring) must recover exactly this case without loosening
# Case 1 (an edit outside an explicitly-approved symbol must still fail).
# ---------------------------------------------------------------------------

def _write_class_with_many_attrs(tmp_path, target_line_1indexed=14, total_attrs=24):
    """A file with one target constant surrounded by enough sibling
    attributes that a hunk can carry more diff context (5 lines each
    side) than the rendered capsule's own padding (_DEFINITION_CONTEXT_
    LINES == 3) without running off either end of the file. Returns the
    written lines (1-indexed access via lines[n-1])."""
    before = target_line_1indexed - 2
    after = total_attrs - before
    lines = ["class Widget(object):\n"]
    for i in range(before):
        lines.append(f"    ATTR_{i} = {i}\n")
    lines.append('    TARGET_CONST = frozenset(["A"])\n')
    for i in range(before, before + after):
        lines.append(f"    ATTR_{i} = {i}\n")
    (tmp_path / "mod.py").write_text("".join(lines), encoding="utf-8")
    return lines


def _wide_context_patch(lines, target_line, context_width=5):
    """A one-line-change hunk whose old-side context is wider than
    _DEFINITION_CONTEXT_LINES (3) on each side -- exactly the shape that
    exposed the bug: fully verifiable against the real file, but not
    verbatim-containable inside the narrower rendered capsule."""
    ctx_before = [" " + lines[i - 1] for i in range(target_line - context_width, target_line)]
    ctx_after = [" " + lines[i - 1] for i in range(target_line + 1, target_line + context_width + 1)]
    removed = "-" + lines[target_line - 1]
    added = '+    TARGET_CONST = frozenset(["A", "B"])\n'
    body = "".join(ctx_before) + removed + added + "".join(ctx_after)
    start = target_line - context_width
    count = context_width * 2 + 1
    return f"--- a/mod.py\n+++ b/mod.py\n@@ -{start},{count} +{start},{count} @@\n" + body


class TestWideContextHunkConformance:
    def test_file_level_ready_edit_wide_context_hunk_becomes_approved(self, tmp_path):
        """Regression for Test 1/3: a file-level (symbol=None) intended
        edit that became ready via identifier_definition_covered (a
        deterministically verified identifier, not a mere symbol=null
        placeholder) must not be classified uncovered_target merely
        because the generated hunk's own diff context is wider than the
        rendered capsule's fixed padding."""
        from utilities.autopatcher.diff_hunk_repair import repair_hunk_headers
        from utilities.autopatcher.remediation_planner import (
            build_final_target_slice, build_intended_edits, check_edit_readiness,
            check_patch_target_conformance, post_patch_recovery_trigger_reasons,
        )

        target_line = 14
        lines = _write_class_with_many_attrs(tmp_path, target_line)
        context = _make_context(constants={"mod.py": {
            "Widget.TARGET_CONST": {
                "qualified_name": "Widget.TARGET_CONST", "class_name": "Widget",
                "name": "TARGET_CONST", "line": target_line, "end_line": target_line,
            },
        }}, repo_path=tmp_path)
        # File-level target: no target_symbols at all -- readiness for this
        # file can ONLY come from identifier_definition_covered (category 2),
        # driven by extended_mechanism naming the real identifier.
        strategy = _make_strategy(
            target_files=["mod.py"], target_symbols=[],
            extended_mechanism="Update TARGET_CONST to include B",
        )
        slice_result = build_final_target_slice(strategy, str(tmp_path), context)
        assert "mod.py" in slice_result.identifier_definition_covered

        intended_edits = build_intended_edits(strategy, slice_result)
        readiness = check_edit_readiness(intended_edits, slice_result)
        assert readiness.edit_source_ready is True
        assert readiness.ready_edits[0].symbol is None  # file-level identity, as documented

        patch = _wide_context_patch(lines, target_line)
        patch, meta = repair_hunk_headers(patch, repo_root=tmp_path)
        assert meta.relocations[0].relocation_reason == "unique_match"

        report = check_patch_target_conformance(patch, meta.relocations, readiness.ready_edits, slice_result)
        assert report.results[0].old_side_status == "old_side_verified"
        assert report.results[0].target_coverage == "approved_target"
        assert report.all_conformant is True
        assert post_patch_recovery_trigger_reasons(report) == []

    def test_symbol_level_ready_edit_wide_context_hunk_becomes_approved(self, tmp_path):
        """Same shape as above, but for an EXPLICIT symbol-level intended
        edit (file + symbol both given) -- proves the fix is general,
        not file-level-specific."""
        from utilities.autopatcher.diff_hunk_repair import repair_hunk_headers
        from utilities.autopatcher.remediation_planner import (
            build_final_target_slice, build_intended_edits, check_edit_readiness,
            check_patch_target_conformance,
        )

        target_line = 14
        lines = _write_class_with_many_attrs(tmp_path, target_line)
        context = _make_context(constants={"mod.py": {
            "Widget.TARGET_CONST": {
                "qualified_name": "Widget.TARGET_CONST", "class_name": "Widget",
                "name": "TARGET_CONST", "line": target_line, "end_line": target_line,
            },
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:Widget.TARGET_CONST"])
        slice_result = build_final_target_slice(strategy, str(tmp_path), context)

        intended_edits = build_intended_edits(strategy, slice_result)
        readiness = check_edit_readiness(intended_edits, slice_result)
        assert readiness.edit_source_ready is True
        assert readiness.ready_edits[0].symbol == "mod.py:Widget.TARGET_CONST"

        patch = _wide_context_patch(lines, target_line)
        patch, meta = repair_hunk_headers(patch, repo_root=tmp_path)

        report = check_patch_target_conformance(patch, meta.relocations, readiness.ready_edits, slice_result)
        assert report.results[0].old_side_status == "old_side_verified"
        assert report.results[0].target_coverage == "approved_target"
        assert report.all_conformant is True

    def test_symbol_level_wide_context_hunk_on_unrelated_content_stays_uncovered(self, tmp_path):
        """Case 1 regression guard: the position-based fallback must
        never widen coverage beyond the approved symbol's own verified
        range. A hunk that is old_side_verified (unique match in the
        real file) but edits unrelated content far from the approved
        symbol must remain uncovered_target/non-conformant even though
        it uses the exact same wide-context hunk shape as the fix
        above."""
        from utilities.autopatcher.diff_hunk_repair import repair_hunk_headers
        from utilities.autopatcher.remediation_planner import (
            build_final_target_slice, build_intended_edits, check_edit_readiness,
            check_patch_target_conformance, post_patch_recovery_trigger_reasons,
        )

        target_line = 14
        lines = _write_class_with_many_attrs(tmp_path, target_line, total_attrs=40)
        context = _make_context(constants={"mod.py": {
            "Widget.TARGET_CONST": {
                "qualified_name": "Widget.TARGET_CONST", "class_name": "Widget",
                "name": "TARGET_CONST", "line": target_line, "end_line": target_line,
            },
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:Widget.TARGET_CONST"])
        slice_result = build_final_target_slice(strategy, str(tmp_path), context)

        intended_edits = build_intended_edits(strategy, slice_result)
        readiness = check_edit_readiness(intended_edits, slice_result)
        assert readiness.edit_source_ready is True

        # Edit a sibling attribute far outside TARGET_CONST's own rendered
        # (padded) range -- never rendered as this ready edit's own source.
        far_line = next(i + 1 for i, l in enumerate(lines) if l.strip().startswith("ATTR_30 "))
        patch = (
            f"--- a/mod.py\n+++ b/mod.py\n@@ -{far_line},1 +{far_line},1 @@\n"
            f"-    ATTR_30 = 30\n+    ATTR_30 = 999\n"
        )
        patch, meta = repair_hunk_headers(patch, repo_root=tmp_path)
        assert meta.relocations[0].relocation_reason == "unique_match"

        report = check_patch_target_conformance(patch, meta.relocations, readiness.ready_edits, slice_result)
        assert report.results[0].old_side_status == "old_side_verified"
        assert report.results[0].target_coverage == "uncovered_target"
        assert report.all_conformant is False
        assert "uncovered_target" in post_patch_recovery_trigger_reasons(report)

    def test_narrow_context_hunk_behavior_is_unchanged(self, tmp_path):
        """Baseline: the ORIGINAL verbatim-text match path (hunk context
        within the rendered capsule's own padding) still governs when it
        already succeeds -- the position-based fallback is additive
        only, never consulted when the primary text match already
        works."""
        from utilities.autopatcher.diff_hunk_repair import repair_hunk_headers
        from utilities.autopatcher.remediation_planner import (
            build_final_target_slice, build_intended_edits, check_edit_readiness,
            check_patch_target_conformance,
        )

        target_line = 14
        lines = _write_class_with_many_attrs(tmp_path, target_line)
        context = _make_context(constants={"mod.py": {
            "Widget.TARGET_CONST": {
                "qualified_name": "Widget.TARGET_CONST", "class_name": "Widget",
                "name": "TARGET_CONST", "line": target_line, "end_line": target_line,
            },
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:Widget.TARGET_CONST"])
        slice_result = build_final_target_slice(strategy, str(tmp_path), context)
        intended_edits = build_intended_edits(strategy, slice_result)
        readiness = check_edit_readiness(intended_edits, slice_result)

        patch = _wide_context_patch(lines, target_line, context_width=1)  # fits the 3-line padding
        patch, meta = repair_hunk_headers(patch, repo_root=tmp_path)

        report = check_patch_target_conformance(patch, meta.relocations, readiness.ready_edits, slice_result)
        assert report.results[0].target_coverage == "approved_target"
        assert report.all_conformant is True


# ---------------------------------------------------------------------------
# _recovered_ready_edit -- promoting a Post-Patch Recovery attempt into the
# reconciled ReadyEdit set used only by the SECOND (post-regeneration) Patch
# Target Conformance check. Promotion must use ONLY deterministically
# verified recovery identity (resolved_file/resolved_target), never the
# original, possibly-unexpected `attempt.file`.
# ---------------------------------------------------------------------------

def _make_attempt(
    file="other.py", trigger_reason="unexpected_file", resolved_file="other.py",
    resolved_target=None, success=True, patch_ready=True, failure_reason=None,
):
    from utilities.autopatcher.remediation_planner import RecoveryTargetAttempt
    return RecoveryTargetAttempt(
        file=file, trigger_reason=trigger_reason, identifiers_considered=[],
        resolved_file=resolved_file, resolved_target=resolved_target,
        target_start_line=None, target_end_line=None, start_line=None, end_line=None,
        enclosing_symbol=None, source_kind=None, source_chars=0,
        patch_ready=patch_ready, identifier_verified_in_window=False,
        success=success, failure_reason=failure_reason,
        target_kind="file", target_identity=None, covered_hunk_indices=[],
    )


class TestRecoveredReadyEditPromotion:
    def test_successful_patch_ready_attempt_becomes_a_real_ready_edit(self):
        """Test 1."""
        from utilities.autopatcher.pipeline import _recovered_ready_edit
        from utilities.autopatcher.remediation_planner import IntendedEdit, ReadyEdit

        attempt = _make_attempt(resolved_file="other.py", resolved_target="X")
        promoted = _recovered_ready_edit(attempt)

        assert isinstance(promoted, ReadyEdit)
        assert promoted.edit == IntendedEdit(file="other.py", symbol="X")
        assert promoted.role == "edit_target"
        assert promoted.file == "other.py"
        assert promoted.symbol == "X"

    def test_promotion_uses_resolved_file_not_original_requested_file(self):
        """Test 2: `attempt.file` (the original, possibly-unexpected
        requested target) must never be used as the promoted identity when
        `resolved_file` differs from it."""
        from utilities.autopatcher.pipeline import _recovered_ready_edit

        attempt = _make_attempt(file="requested.py", resolved_file="actual_source.py", resolved_target="Y")
        promoted = _recovered_ready_edit(attempt)

        assert promoted is not None
        assert promoted.file == "actual_source.py"
        assert promoted.edit.file == "actual_source.py"
        assert promoted.file != "requested.py"

    def test_success_without_patch_ready_is_not_promoted(self):
        """Test 3."""
        from utilities.autopatcher.pipeline import _recovered_ready_edit

        attempt = _make_attempt(success=True, patch_ready=False, resolved_file="other.py")
        assert _recovered_ready_edit(attempt) is None

    def test_attempt_with_no_resolved_file_is_not_promoted(self):
        """Test 4."""
        from utilities.autopatcher.pipeline import _recovered_ready_edit

        attempt = _make_attempt(success=True, patch_ready=True, resolved_file=None)
        assert _recovered_ready_edit(attempt) is None

    def test_failed_attempt_is_not_promoted(self):
        """Extra safety net: success=False alone must also block promotion,
        independent of patch_ready/resolved_file."""
        from utilities.autopatcher.pipeline import _recovered_ready_edit

        attempt = _make_attempt(success=False, patch_ready=False, resolved_file="other.py")
        assert _recovered_ready_edit(attempt) is None


# ---------------------------------------------------------------------------
# Evidence-floor guard: a recovered target may only be promoted when its
# resolved FILE already had prior support before Patch Generation ran
# (Target Discovery's own target_files, or Final Strategy's target_files).
# _recovered_ready_edit's checks prove the recovered SOURCE is real and
# patch-ready; they do not, by themselves, prove the file was ever an
# approved candidate in the first place -- this is the second, independent
# gate applied at the reconciliation call site.
# ---------------------------------------------------------------------------

def _is_promoted(attempt, plan_result, strategy_result):
    """Mirrors exactly how pipeline.run()'s reconciliation loop combines
    _recovered_ready_edit with _prior_supported_target_files."""
    from utilities.autopatcher.pipeline import _prior_supported_target_files, _recovered_ready_edit
    promoted = _recovered_ready_edit(attempt)
    if promoted is None:
        return False
    return promoted.file in _prior_supported_target_files(plan_result, strategy_result)


class TestRecoveredTargetEvidenceFloor:
    def test_file_present_in_target_discovery_but_not_final_strategy_is_promoted(self):
        """Test 1: the urllib3-shape case -- a file was already named by
        Target Discovery, then dropped by Final Strategy, but recovery may
        still reconcile it."""
        from utilities.autopatcher.remediation_planner import RemediationPlanResult

        plan = RemediationPlanResult(rendered="", target_files=["retry.py"], target_symbols=[])
        strategy = _make_strategy(target_files=["mod.py"])
        attempt = _make_attempt(
            success=True, patch_ready=True, resolved_file="retry.py", resolved_target="SOME_CONST",
        )
        assert _is_promoted(attempt, plan, strategy) is True

    def test_file_present_in_final_strategy_is_promoted(self):
        """Test 2."""
        from utilities.autopatcher.remediation_planner import RemediationPlanResult

        plan = RemediationPlanResult(rendered="", target_files=[], target_symbols=[])
        strategy = _make_strategy(target_files=["mod.py"])
        attempt = _make_attempt(
            success=True, patch_ready=True, resolved_file="mod.py", resolved_target="CONST_A",
        )
        assert _is_promoted(attempt, plan, strategy) is True

    def test_file_absent_from_both_is_not_promoted(self):
        """Test 3: Patch Generation must not be able to invent a brand-new
        target file with zero prior evidence and have recovery launder it
        into an approved target merely because its source can be read."""
        from utilities.autopatcher.remediation_planner import RemediationPlanResult

        plan = RemediationPlanResult(rendered="", target_files=["mod.py"], target_symbols=[])
        strategy = _make_strategy(target_files=["mod.py"])
        attempt = _make_attempt(
            success=True, patch_ready=True, resolved_file="invented.py", resolved_target="Z",
        )
        assert _is_promoted(attempt, plan, strategy) is False

    def test_missing_plan_and_strategy_yield_no_prior_support(self):
        """A recovery target must never be promoted merely because there is
        no prior evidence to check against."""
        attempt = _make_attempt(success=True, patch_ready=True, resolved_file="mod.py", resolved_target="CONST_A")
        assert _is_promoted(attempt, None, None) is False


# ---------------------------------------------------------------------------
# recover_post_patch_source
# ---------------------------------------------------------------------------

class TestPostPatchRecovery:
    def test_not_triggered_when_conformant(self, tmp_path):
        """Test 1 (recovery side)."""
        from utilities.autopatcher.remediation_planner import (
            PatchConformanceReport, recover_post_patch_source,
        )
        conformance = PatchConformanceReport(
            results=[], all_conformant=True, edited_files=["mod.py"],
            unexpected_files=[], uncovered_files=[], no_match_files=[],
        )
        result = recover_post_patch_source(
            _make_strategy(), str(tmp_path), None, _make_slice_result(), conformance, "",
        )
        assert result.triggered is False
        assert result.ready_for_regeneration is False

    def test_recovery_retrieves_exact_repository_source_via_identifier(self, tmp_path):
        """Test 9 + Test 13: an identifier appearing in the hunk resolves
        to its own exact, real definition -- never invented text."""
        from utilities.autopatcher.remediation_planner import (
            PatchConformanceReport, recover_post_patch_source,
        )
        (tmp_path / "mod.py").write_text("CONST_B = 42\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_B": {"qualified_name": "CONST_B", "class_name": None, "name": "CONST_B", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=[])
        conformance = PatchConformanceReport(
            results=[], all_conformant=False, edited_files=["mod.py"],
            unexpected_files=["mod.py"], uncovered_files=[], no_match_files=[],
        )
        patch = "--- a/mod.py\n+++ b/mod.py\n@@ -1,1 +1,1 @@\n-CONST_B = 42\n+CONST_B = 43\n"

        result = recover_post_patch_source(
            strategy, str(tmp_path), context, _make_slice_result(), conformance, patch,
        )
        assert result.triggered is True
        assert result.attempts[0].success is True
        assert result.attempts[0].resolved_file == "mod.py"
        assert "CONST_B = 42" in result.slice_result.rendered
        assert result.ready_for_regeneration is True

    def test_recovery_never_crosses_into_a_different_file(self, tmp_path):
        """Test 10: a same-named identifier in a DIFFERENT file must
        never satisfy recovery for the actual target file."""
        from utilities.autopatcher.remediation_planner import (
            PatchConformanceReport, recover_post_patch_source,
        )
        (tmp_path / "mod.py").write_text("x = 1\n", encoding="utf-8")  # no CONST_B here
        (tmp_path / "other.py").write_text("CONST_B = 999\n", encoding="utf-8")
        context = _make_context(constants={"other.py": {
            "CONST_B": {"qualified_name": "CONST_B", "class_name": None, "name": "CONST_B", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=[])
        conformance = PatchConformanceReport(
            results=[], all_conformant=False, edited_files=["mod.py"],
            unexpected_files=["mod.py"], uncovered_files=[], no_match_files=[],
        )
        patch = "--- a/mod.py\n+++ b/mod.py\n@@ -1,1 +1,1 @@\n-x = 1\n+CONST_B = 1\n"

        result = recover_post_patch_source(
            strategy, str(tmp_path), context, _make_slice_result(), conformance, patch,
        )
        assert result.attempts[0].success is False
        assert "CONST_B = 999" not in result.slice_result.rendered

    def test_unsafe_target_file_path_fails_closed(self, tmp_path):
        """Test 11."""
        from utilities.autopatcher.remediation_planner import (
            PatchConformanceReport, recover_post_patch_source,
        )
        conformance = PatchConformanceReport(
            results=[], all_conformant=False, edited_files=["../outside.py"],
            unexpected_files=["../outside.py"], uncovered_files=[], no_match_files=[],
        )
        result = recover_post_patch_source(
            _make_strategy(), str(tmp_path), _make_context(repo_path=tmp_path),
            _make_slice_result(), conformance, "",
        )
        assert result.attempts[0].success is False
        assert result.attempts[0].failure_reason == "unsafe_file_path"
        assert result.ready_for_regeneration is False

    def test_recovery_source_is_bounded(self, tmp_path, monkeypatch):
        """Test 14."""
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.remediation_planner import PatchConformanceReport

        (tmp_path / "mod.py").write_text("CONST_B = 42\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_B": {"qualified_name": "CONST_B", "class_name": None, "name": "CONST_B", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        conformance = PatchConformanceReport(
            results=[], all_conformant=False, edited_files=["mod.py"],
            unexpected_files=["mod.py"], uncovered_files=[], no_match_files=[],
        )
        patch = "--- a/mod.py\n+++ b/mod.py\n@@ -1,1 +1,1 @@\n-CONST_B = 42\n+CONST_B = 43\n"
        monkeypatch.setattr(rp, "MAX_POST_PATCH_SOURCE_CHARS", 1)

        result = rp.recover_post_patch_source(
            _make_strategy(), str(tmp_path), context, _make_slice_result(), conformance, patch,
        )
        assert result.attempts[0].success is False
        assert result.attempts[0].failure_reason == "target_budget_exhausted"

    def test_recovery_handles_multiple_failing_hunks_in_one_round(self, tmp_path):
        """Test 15."""
        from utilities.autopatcher.remediation_planner import (
            PatchConformanceReport, recover_post_patch_source,
        )
        (tmp_path / "a.py").write_text("CONST_A = 1\n", encoding="utf-8")
        (tmp_path / "b.py").write_text("CONST_B = 2\n", encoding="utf-8")
        context = _make_context(constants={
            "a.py": {"CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1}},
            "b.py": {"CONST_B": {"qualified_name": "CONST_B", "class_name": None, "name": "CONST_B", "line": 1, "end_line": 1}},
        }, repo_path=tmp_path)
        conformance = PatchConformanceReport(
            results=[], all_conformant=False, edited_files=["a.py", "b.py"],
            unexpected_files=["a.py", "b.py"], uncovered_files=[], no_match_files=[],
        )
        patch = (
            "--- a/a.py\n+++ b/a.py\n@@ -1,1 +1,1 @@\n-CONST_A = 1\n+CONST_A = 9\n"
            "--- a/b.py\n+++ b/b.py\n@@ -1,1 +1,1 @@\n-CONST_B = 2\n+CONST_B = 9\n"
        )

        result = recover_post_patch_source(
            _make_strategy(), str(tmp_path), context, _make_slice_result(), conformance, patch,
        )
        assert len(result.attempts) == 2
        assert all(a.success for a in result.attempts)
        assert result.ready_for_regeneration is True

    def test_recovery_capped_at_three_targets(self, tmp_path):
        """Test 16."""
        from utilities.autopatcher.remediation_planner import PatchConformanceReport
        from utilities.autopatcher import remediation_planner as rp

        files = [f"f{i}.py" for i in range(4)]
        conformance = PatchConformanceReport(
            results=[], all_conformant=False, edited_files=files,
            unexpected_files=files, uncovered_files=[], no_match_files=[],
        )
        result = rp.recover_post_patch_source(
            _make_strategy(), str(tmp_path), _make_context(repo_path=tmp_path),
            _make_slice_result(), conformance, "",
        )
        assert result.attempts == []
        assert result.failure_reason == "too_many_recovery_targets"
        assert result.ready_for_regeneration is False

    def test_partial_recovery_evidence_does_not_permit_regeneration(self, tmp_path):
        """Test 27."""
        from utilities.autopatcher.remediation_planner import (
            PatchConformanceReport, recover_post_patch_source,
        )
        (tmp_path / "a.py").write_text("CONST_A = 1\n", encoding="utf-8")
        # b.py has NOTHING resolvable at all.
        (tmp_path / "b.py").write_text("x = 1\n", encoding="utf-8")
        context = _make_context(constants={
            "a.py": {"CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1}},
        }, repo_path=tmp_path)
        conformance = PatchConformanceReport(
            results=[], all_conformant=False, edited_files=["a.py", "b.py"],
            unexpected_files=["a.py", "b.py"], uncovered_files=[], no_match_files=[],
        )
        patch = (
            "--- a/a.py\n+++ b/a.py\n@@ -1,1 +1,1 @@\n-CONST_A = 1\n+CONST_A = 9\n"
            "--- a/b.py\n+++ b/b.py\n@@ -1,1 +1,1 @@\n-NoSuchIdentifier = 1\n+NoSuchIdentifier = 9\n"
        )

        result = recover_post_patch_source(
            _make_strategy(), str(tmp_path), context, _make_slice_result(), conformance, patch,
        )
        assert result.ready_for_regeneration is False
        assert result.failure_reason == "partial_recovery_evidence"


# ---------------------------------------------------------------------------
# Hunk-level recovery coverage -- the GitPython-shaped regression: one FILE
# with several independent failing hunks must not be declared ready for
# regeneration merely because ONE window/attempt for that file "succeeded".
# Every recovery-triggering hunk (PatchConformanceReport.results) must be
# individually verified present in recovered source.
# ---------------------------------------------------------------------------

class TestHunkLevelRecoveryCoverage:
    def test_one_file_multiple_hunks_partial_coverage_stays_not_ready(self, tmp_path):
        """Required regression 1: three independent, disjoint edit regions
        in one file; recovery's single resolved window only covers the
        FIRST one (CONST_A) -- CONST_B/CONST_C sit far enough away (each
        in its own class, so never grouped as siblings) that the window
        never reaches them. ready_for_regeneration must stay False with
        partial_hunk_coverage, even though the one attempt for this file
        itself "succeeded" at building a window."""
        from utilities.autopatcher.remediation_planner import (
            PatchConformanceReport, PatchTargetConformanceResult, recover_post_patch_source,
        )

        lines = (
            "class GroupA:\n    CONST_A = 1\n"
            + "".join(f"    filler_a{i} = {i}\n" for i in range(1, 12))
            + "class GroupB:\n    CONST_B = 2\n"
            + "".join(f"    filler_b{i} = {i}\n" for i in range(1, 12))
            + "class GroupC:\n    CONST_C = 3\n"
        )
        (tmp_path / "mod.py").write_text(lines, encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "GroupA.CONST_A": {"qualified_name": "GroupA.CONST_A", "class_name": "GroupA", "name": "CONST_A", "line": 2, "end_line": 2},
            "GroupB.CONST_B": {"qualified_name": "GroupB.CONST_B", "class_name": "GroupB", "name": "CONST_B", "line": 15, "end_line": 15},
            "GroupC.CONST_C": {"qualified_name": "GroupC.CONST_C", "class_name": "GroupC", "name": "CONST_C", "line": 28, "end_line": 28},
        }}, repo_path=tmp_path)
        patch = (
            "--- a/mod.py\n+++ b/mod.py\n"
            "@@ -2,1 +2,1 @@\n-    CONST_A = 1\n+    CONST_A = 9\n"
            "@@ -15,1 +15,1 @@\n-    CONST_B = 2\n+    CONST_B = 9\n"
            "@@ -28,1 +28,1 @@\n-    CONST_C = 3\n+    CONST_C = 9\n"
        )
        conformance = PatchConformanceReport(
            results=[
                PatchTargetConformanceResult(file="mod.py", hunk_index=0, target_coverage="uncovered_target", old_side_status="old_side_verified", conformant=False),
                PatchTargetConformanceResult(file="mod.py", hunk_index=1, target_coverage="uncovered_target", old_side_status="old_side_verified", conformant=False),
                PatchTargetConformanceResult(file="mod.py", hunk_index=2, target_coverage="uncovered_target", old_side_status="old_side_verified", conformant=False),
            ],
            all_conformant=False, edited_files=["mod.py"],
            unexpected_files=[], uncovered_files=["mod.py"], no_match_files=[],
        )

        result = recover_post_patch_source(
            _make_strategy(), str(tmp_path), context, _make_slice_result(), conformance, patch,
        )
        assert result.attempts[0].success is True  # the window itself was built fine
        assert result.attempts[0].covered_hunk_indices == [0]  # only CONST_A's hunk
        assert result.ready_for_regeneration is False
        assert result.failure_reason == "partial_hunk_coverage"

    def test_one_file_window_genuinely_covers_all_failing_hunks(self, tmp_path):
        """Required regression 2: three failing hunks whose real content
        all sits inside ONE small sibling-constant group -- the single
        resolved window genuinely covers all three, so ready_for_regeneration
        may become True."""
        from utilities.autopatcher.remediation_planner import (
            PatchConformanceReport, PatchTargetConformanceResult, recover_post_patch_source,
        )

        (tmp_path / "mod.py").write_text(
            "class Policy:\n    CONST_A = 1\n    CONST_B = 2\n    CONST_C = 3\n", encoding="utf-8",
        )
        context = _make_context(constants={"mod.py": {
            "Policy.CONST_A": {"qualified_name": "Policy.CONST_A", "class_name": "Policy", "name": "CONST_A", "line": 2, "end_line": 2},
            "Policy.CONST_B": {"qualified_name": "Policy.CONST_B", "class_name": "Policy", "name": "CONST_B", "line": 3, "end_line": 3},
            "Policy.CONST_C": {"qualified_name": "Policy.CONST_C", "class_name": "Policy", "name": "CONST_C", "line": 4, "end_line": 4},
        }}, repo_path=tmp_path)
        patch = (
            "--- a/mod.py\n+++ b/mod.py\n"
            "@@ -2,1 +2,1 @@\n-    CONST_A = 1\n+    CONST_A = 9\n"
            "@@ -3,1 +3,1 @@\n-    CONST_B = 2\n+    CONST_B = 9\n"
            "@@ -4,1 +4,1 @@\n-    CONST_C = 3\n+    CONST_C = 9\n"
        )
        conformance = PatchConformanceReport(
            results=[
                PatchTargetConformanceResult(file="mod.py", hunk_index=0, target_coverage="uncovered_target", old_side_status="old_side_verified", conformant=False),
                PatchTargetConformanceResult(file="mod.py", hunk_index=1, target_coverage="uncovered_target", old_side_status="old_side_verified", conformant=False),
                PatchTargetConformanceResult(file="mod.py", hunk_index=2, target_coverage="uncovered_target", old_side_status="old_side_verified", conformant=False),
            ],
            all_conformant=False, edited_files=["mod.py"],
            unexpected_files=[], uncovered_files=["mod.py"], no_match_files=[],
        )

        result = recover_post_patch_source(
            _make_strategy(), str(tmp_path), context, _make_slice_result(), conformance, patch,
        )
        assert sorted(result.attempts[0].covered_hunk_indices) == [0, 1, 2]
        assert result.ready_for_regeneration is True

    def test_multiple_files_every_failing_hunk_covered(self, tmp_path):
        """Required regression 3: two files, one failing hunk each, both
        genuinely covered -- ready_for_regeneration may become True."""
        from utilities.autopatcher.remediation_planner import (
            PatchConformanceReport, PatchTargetConformanceResult, recover_post_patch_source,
        )

        (tmp_path / "a.py").write_text("CONST_A = 1\n", encoding="utf-8")
        (tmp_path / "b.py").write_text("CONST_B = 2\n", encoding="utf-8")
        context = _make_context(constants={
            "a.py": {"CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1}},
            "b.py": {"CONST_B": {"qualified_name": "CONST_B", "class_name": None, "name": "CONST_B", "line": 1, "end_line": 1}},
        }, repo_path=tmp_path)
        patch = (
            "--- a/a.py\n+++ b/a.py\n@@ -1,1 +1,1 @@\n-CONST_A = 1\n+CONST_A = 9\n"
            "--- a/b.py\n+++ b/b.py\n@@ -1,1 +1,1 @@\n-CONST_B = 2\n+CONST_B = 9\n"
        )
        conformance = PatchConformanceReport(
            results=[
                PatchTargetConformanceResult(file="a.py", hunk_index=0, target_coverage="unexpected_file", old_side_status="old_side_verified", conformant=False),
                PatchTargetConformanceResult(file="b.py", hunk_index=0, target_coverage="unexpected_file", old_side_status="old_side_verified", conformant=False),
            ],
            all_conformant=False, edited_files=["a.py", "b.py"],
            unexpected_files=["a.py", "b.py"], uncovered_files=[], no_match_files=[],
        )

        result = recover_post_patch_source(
            _make_strategy(), str(tmp_path), context, _make_slice_result(), conformance, patch,
        )
        assert result.attempts[0].covered_hunk_indices == [0]
        assert result.attempts[1].covered_hunk_indices == [0]
        assert result.ready_for_regeneration is True


# ---------------------------------------------------------------------------
# Recovery eligibility -- RecoveryTarget/build_recovery_targets. Recovery
# may investigate a file that is EITHER a current ReadyEdit OR has prior
# support (Target Discovery/Final Strategy); a file with neither fails
# closed immediately, before any retrieval. Deliberately never consumed by
# check_patch_target_conformance (see that function's own docstring).
# ---------------------------------------------------------------------------

class TestRecoveryEligibility:
    def test_recovery_targets_none_preserves_permissive_backward_compatible_behavior(self, tmp_path):
        """Required regression 6: recovery_targets=None means no
        eligibility list was modeled by this caller at all -- every
        failing file is still attempted exactly as before eligibility
        existed."""
        from utilities.autopatcher.remediation_planner import (
            PatchConformanceReport, recover_post_patch_source,
        )

        (tmp_path / "mod.py").write_text("CONST_B = 42\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_B": {"qualified_name": "CONST_B", "class_name": None, "name": "CONST_B", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        conformance = PatchConformanceReport(
            results=[], all_conformant=False, edited_files=["mod.py"],
            unexpected_files=["mod.py"], uncovered_files=[], no_match_files=[],
        )
        patch = "--- a/mod.py\n+++ b/mod.py\n@@ -1,1 +1,1 @@\n-CONST_B = 42\n+CONST_B = 43\n"

        result = recover_post_patch_source(
            _make_strategy(), str(tmp_path), context, _make_slice_result(), conformance, patch,
            recovery_targets=None,
        )
        assert result.attempts[0].success is True
        assert result.attempts[0].failure_reason is None
        assert result.ready_for_regeneration is True

    def test_prior_supported_file_without_ready_edit_is_eligible(self, tmp_path):
        """Required regression 4 (A/B, focused at the recovery level): B
        has prior support (Target Discovery/Final Strategy) but no
        ReadyEdit at all -- ReadyEdit approves only A. B must still be
        eligible and recoverable."""
        from utilities.autopatcher.remediation_planner import (
            PatchConformanceReport, build_recovery_targets, recover_post_patch_source,
        )

        (tmp_path / "b.py").write_text("CONST_B = 1\n", encoding="utf-8")
        context = _make_context(constants={"b.py": {
            "CONST_B": {"qualified_name": "CONST_B", "class_name": None, "name": "CONST_B", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        conformance = PatchConformanceReport(
            results=[], all_conformant=False, edited_files=["b.py"],
            unexpected_files=["b.py"], uncovered_files=[], no_match_files=[],
        )
        patch = "--- a/b.py\n+++ b/b.py\n@@ -1,1 +1,1 @@\n-CONST_B = 1\n+CONST_B = 9\n"

        ready_edits = [_make_ready_edit("a.py", "a.py:CONST_A")]  # only A is a ready edit
        recovery_targets = build_recovery_targets(ready_edits, prior_supported_files={"a.py", "b.py"})

        result = recover_post_patch_source(
            _make_strategy(), str(tmp_path), context, _make_slice_result(), conformance, patch,
            recovery_targets=recovery_targets,
        )
        assert result.attempts[0].success is True
        assert result.attempts[0].failure_reason != "not_recovery_eligible"
        assert result.ready_for_regeneration is True

    def test_ineligible_file_fails_closed_with_no_retrieval(self, tmp_path, monkeypatch):
        """Required regression 5: C is absent from ReadyEdit, Target
        Discovery, and Final Strategy entirely. Recovery must fail C
        closed immediately as not_recovery_eligible, WITHOUT performing
        any retrieval -- proven here by tracking that _verify_file (the
        first thing any real attempt calls) is never invoked for it."""
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.remediation_planner import PatchConformanceReport

        (tmp_path / "c.py").write_text("Z = 1\n", encoding="utf-8")
        context = _make_context(constants={"c.py": {
            "Z": {"qualified_name": "Z", "class_name": None, "name": "Z", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        conformance = PatchConformanceReport(
            results=[], all_conformant=False, edited_files=["c.py"],
            unexpected_files=["c.py"], uncovered_files=[], no_match_files=[],
        )
        patch = "--- a/c.py\n+++ b/c.py\n@@ -1,1 +1,1 @@\n-Z = 1\n+Z = 2\n"

        calls: list = []
        real_verify_file = rp._verify_file

        def _tracking_verify_file(file, root):
            calls.append(file)
            return real_verify_file(file, root)

        monkeypatch.setattr(rp, "_verify_file", _tracking_verify_file)

        result = rp.recover_post_patch_source(
            _make_strategy(), str(tmp_path), context, _make_slice_result(), conformance, patch,
            recovery_targets=[],  # eligibility enforced; nothing eligible
        )
        assert calls == []  # _verify_file never called -- no retrieval for the ineligible target
        assert len(result.attempts) == 1
        assert result.attempts[0].success is False
        assert result.attempts[0].failure_reason == "not_recovery_eligible"
        assert result.ready_for_regeneration is False


# ---------------------------------------------------------------------------
# Patch-ready recovery window -- Slice 4's own fix for the urllib3-run
# failure: a recovered "exact definition" was reasoning-ready but not a
# sufficiently patch-ready, contiguous window (a real hunk's own target sat
# at the edge of, or between, two independently-padded, disjoint blocks for
# nearby identifiers), so the regenerated diff's own context lines failed
# relocation against the real file. _build_post_patch_window/
# recover_post_patch_source now build ONE contiguous, verbatim, bounded
# window per recovery target instead.
# ---------------------------------------------------------------------------

class TestPostPatchWindowConstruction:
    """Unit-level coverage of _build_post_patch_window itself."""

    def test_exact_constant_definition_becomes_contiguous_patch_ready_window(self, tmp_path):
        """Test 1. A single, sibling-less constant resolves to one
        contiguous window containing its own exact definition."""
        from utilities.autopatcher.remediation_planner import _build_post_patch_window

        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)

        window = _build_post_patch_window("mod.py", ["CONST_A"], [], context, try_old_side_anchor=False)
        assert window is not None
        assert window.source_kind in ("patch_ready_window", "enclosing_symbol")
        assert "CONST_A = 1" in window.source
        assert window.start <= window.target_start <= window.target_end <= window.end

    def test_target_line_is_not_split_across_two_adjacent_blocks(self, tmp_path):
        """Test 2. Three sibling class attributes, in order -- the middle
        one's own window must be a SINGLE contiguous block containing all
        three, never two independently-selected fragments."""
        from utilities.autopatcher.remediation_planner import _build_post_patch_window, _render_definition_block

        (tmp_path / "policy.py").write_text(
            "class Policy:\n"
            "    FIRST_CONST = 1\n"
            "    TARGET_CONST = 2\n"
            "    LAST_CONST = 3\n",
            encoding="utf-8",
        )
        context = _make_context(constants={"policy.py": {
            "Policy.FIRST_CONST": {"qualified_name": "Policy.FIRST_CONST", "class_name": "Policy", "name": "FIRST_CONST", "line": 2, "end_line": 2},
            "Policy.TARGET_CONST": {"qualified_name": "Policy.TARGET_CONST", "class_name": "Policy", "name": "TARGET_CONST", "line": 3, "end_line": 3},
            "Policy.LAST_CONST": {"qualified_name": "Policy.LAST_CONST", "class_name": "Policy", "name": "LAST_CONST", "line": 4, "end_line": 4},
        }}, repo_path=tmp_path)

        window = _build_post_patch_window("policy.py", ["TARGET_CONST"], [], context, try_old_side_anchor=False)
        assert window is not None
        assert "FIRST_CONST" in window.source
        assert "TARGET_CONST" in window.source
        assert "LAST_CONST" in window.source
        rendered = _render_definition_block(window.file, window.label, window.start, window.end, window.source)
        assert rendered.count("#### Target definition:") == 1

    def test_window_contains_exact_unchanged_lines_before_and_after(self, tmp_path):
        """Test 3. A module-level constant with no siblings still gets
        POST_PATCH_WINDOW_CONTEXT_LINES of real, unchanged repository text
        on each side -- never just its own bare definition line."""
        from utilities.autopatcher.remediation_planner import _build_post_patch_window

        lines = [f"filler_before_{i} = {i}\n" for i in range(5)]
        lines.append("CONST_A = 1\n")
        lines += [f"filler_after_{i} = {i}\n" for i in range(5)]
        (tmp_path / "mod.py").write_text("".join(lines), encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 6, "end_line": 6},
        }}, repo_path=tmp_path)

        window = _build_post_patch_window("mod.py", ["CONST_A"], [], context, try_old_side_anchor=False)
        assert window is not None
        assert "filler_before_4 = 4" in window.source
        assert "filler_after_0 = 0" in window.source
        assert "CONST_A = 1" in window.source

    def test_window_clamped_to_known_enclosing_symbol(self, tmp_path):
        """Test 4. A large enclosing constant group -- too big to
        include whole -- clamps its padded window to the group's own
        bounds, never spilling into a DIFFERENT, adjacent enclosing
        unit (class B, immediately following class A)."""
        from utilities.autopatcher.remediation_planner import _build_post_patch_window

        lines = ["class A:"]
        for i in range(500):
            lines.append(f"    A{i} = {i}")
        lines[498] = "    TARGET_CONST = 999"  # near the end of A's own group
        lines.append("class B:")
        for i in range(5):
            lines.append(f"    B{i} = {i}")
        (tmp_path / "mod.py").write_text("\n".join(lines) + "\n", encoding="utf-8")

        constants = {"mod.py": {}}
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or ":" in stripped:
                continue
            name = stripped.split(" ")[0]
            cls = "A" if idx < len(lines) - 6 else "B"
            constants["mod.py"][f"{cls}.{name}"] = {
                "qualified_name": f"{cls}.{name}", "class_name": cls, "name": name,
                "line": idx + 1, "end_line": idx + 1,
            }
        context = _make_context(constants=constants, repo_path=tmp_path)
        class_b_start_line = next(i for i, l in enumerate(lines) if l.strip() == "class B:") + 1

        window = _build_post_patch_window("mod.py", ["TARGET_CONST"], [], context, try_old_side_anchor=False)
        assert window is not None
        assert window.end < class_b_start_line
        assert "B0 = 0" not in window.source
        assert "TARGET_CONST" in window.source

    def test_large_enclosing_function_uses_bounded_focused_window(self, tmp_path):
        """Test 5. A function far larger than the "small enclosing unit"
        cap must never be included whole -- a bounded, focused window
        (clamped to the function's own bounds) is used instead."""
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.remediation_planner import _build_post_patch_window

        body_lines = ["def big_func():"]
        body_lines += [f"    x{i} = {i}" for i in range(400)]
        src = "\n".join(body_lines) + "\n"
        assert len(src) > rp._POST_PATCH_SMALL_ENCLOSING_UNIT_CHARS
        (tmp_path / "big.py").write_text(src, encoding="utf-8")
        context = _make_context(functions={
            "big.py:big_func": {"name": "big_func", "className": None, "startLine": 1, "endLine": len(body_lines), "code": src},
        }, repo_path=tmp_path)

        window = _build_post_patch_window("big.py", ["big_func"], [], context, try_old_side_anchor=False)
        assert window is not None
        assert window.source_kind == "patch_ready_window"
        assert window.enclosing_symbol == "big_func"
        assert window.start >= 1
        assert window.end <= len(body_lines)
        assert len(window.source) < len(src)  # focused, not the whole function

    def test_small_enclosing_function_included_completely(self, tmp_path):
        """Test 6. A function small enough to fit the "small enclosing
        unit" cap is included in full -- no padding needed, since its
        own body already contains all its internal context."""
        from utilities.autopatcher.remediation_planner import _build_post_patch_window

        src = "def small_func():\n    TARGET = 1\n    return TARGET\n"
        (tmp_path / "small.py").write_text(src, encoding="utf-8")
        context = _make_context(functions={
            "small.py:small_func": {"name": "small_func", "className": None, "startLine": 1, "endLine": 3, "code": src},
        }, repo_path=tmp_path)

        window = _build_post_patch_window("small.py", ["small_func"], [], context, try_old_side_anchor=False)
        assert window is not None
        assert window.source_kind == "enclosing_symbol"
        assert window.source == src
        assert window.start == 1 and window.end == 3

    def test_source_remains_verbatim(self, tmp_path):
        """Test 7. The window's own source text is an exact substring of
        the real file's content -- never reformatted, trimmed, or
        reconstructed."""
        from utilities.autopatcher.remediation_planner import _build_post_patch_window

        real_text = "CONST_A = 1\nCONST_B = 2\nCONST_C = 3\n"
        (tmp_path / "mod.py").write_text(real_text, encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_B": {"qualified_name": "CONST_B", "class_name": None, "name": "CONST_B", "line": 2, "end_line": 2},
        }}, repo_path=tmp_path)

        window = _build_post_patch_window("mod.py", ["CONST_B"], [], context, try_old_side_anchor=False)
        assert window is not None
        assert window.source in real_text
        real_lines = real_text.splitlines()
        window_lines = window.source.splitlines()
        assert real_lines[window.start - 1: window.start - 1 + len(window_lines)] == window_lines

    def test_no_enclosing_symbol_uses_bounded_fallback(self, tmp_path):
        """A module-level constant with no siblings in the same scope has
        no real "enclosing group" -- _build_post_patch_window must still
        return a bounded (not whole-file) padded window, never fail."""
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.remediation_planner import _build_post_patch_window

        lines = [f"OTHER_{i} = {i}\n" for i in range(50)]
        lines.insert(25, "CONST_A = 1\n")
        (tmp_path / "mod.py").write_text("".join(lines), encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 26, "end_line": 26},
        }}, repo_path=tmp_path)

        window = _build_post_patch_window("mod.py", ["CONST_A"], [], context, try_old_side_anchor=False)
        assert window is not None
        assert window.enclosing_symbol is None
        assert window.source_kind == "patch_ready_window"
        expected_span = 2 * rp.POST_PATCH_WINDOW_CONTEXT_LINES + 1
        assert len(window.source.splitlines()) <= expected_span + 1


class TestPostPatchWindowBudgetAndTrace:
    """Integration-level coverage through recover_post_patch_source
    itself: budget enforcement, fail-closed behavior, and the extended
    recovery trace."""

    def test_window_respects_max_post_patch_source_chars(self, tmp_path, monkeypatch):
        """Test 8. A budget too small for the resolved window must fail
        closed as target_budget_exhausted -- never silently degrade to a
        smaller, possibly insufficient block."""
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.remediation_planner import PatchConformanceReport

        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        conformance = PatchConformanceReport(
            results=[], all_conformant=False, edited_files=["mod.py"],
            unexpected_files=["mod.py"], uncovered_files=[], no_match_files=[],
        )
        patch = "--- a/mod.py\n+++ b/mod.py\n@@ -1,1 +1,1 @@\n-CONST_A = 1\n+CONST_A = 2\n"
        monkeypatch.setattr(rp, "MAX_POST_PATCH_SOURCE_CHARS", 5)

        result = rp.recover_post_patch_source(
            _make_strategy(), str(tmp_path), context, _make_slice_result(), conformance, patch,
        )
        assert result.attempts[0].success is False
        assert result.attempts[0].failure_reason == "target_budget_exhausted"
        assert result.attempts[0].patch_ready is False

    def test_truncated_target_coverage_fails_closed(self, tmp_path, monkeypatch):
        """Test 9. When a resolved window cannot fit, recovery must not
        regenerate from partial evidence -- ready_for_regeneration stays
        False and the rendered slice gains nothing for that target."""
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.remediation_planner import PatchConformanceReport

        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        conformance = PatchConformanceReport(
            results=[], all_conformant=False, edited_files=["mod.py"],
            unexpected_files=["mod.py"], uncovered_files=[], no_match_files=[],
        )
        patch = "--- a/mod.py\n+++ b/mod.py\n@@ -1,1 +1,1 @@\n-CONST_A = 1\n+CONST_A = 2\n"
        monkeypatch.setattr(rp, "MAX_POST_PATCH_SOURCE_CHARS", 5)
        initial_slice = _make_slice_result()

        result = rp.recover_post_patch_source(
            _make_strategy(), str(tmp_path), context, initial_slice, conformance, patch,
        )
        assert result.ready_for_regeneration is False
        assert "CONST_A" not in result.slice_result.rendered

    def test_recovery_trace_reports_final_window_and_patch_ready_state(self, tmp_path):
        """Test 10. A successful recovery's trace names the resolved
        target's own span, the FINAL window's (possibly wider) span, the
        enclosing symbol when one was used, and patch_ready=True."""
        from utilities.autopatcher.remediation_planner import (
            PatchConformanceReport, recover_post_patch_source,
        )
        (tmp_path / "policy.py").write_text(
            "class Policy:\n    FIRST_CONST = 1\n    TARGET_CONST = 2\n", encoding="utf-8",
        )
        context = _make_context(constants={"policy.py": {
            "Policy.FIRST_CONST": {"qualified_name": "Policy.FIRST_CONST", "class_name": "Policy", "name": "FIRST_CONST", "line": 2, "end_line": 2},
            "Policy.TARGET_CONST": {"qualified_name": "Policy.TARGET_CONST", "class_name": "Policy", "name": "TARGET_CONST", "line": 3, "end_line": 3},
        }}, repo_path=tmp_path)
        conformance = PatchConformanceReport(
            results=[], all_conformant=False, edited_files=["policy.py"],
            unexpected_files=["policy.py"], uncovered_files=[], no_match_files=[],
        )
        patch = "--- a/policy.py\n+++ b/policy.py\n@@ -3,1 +3,1 @@\n-    TARGET_CONST = 2\n+    TARGET_CONST = 3\n"

        result = recover_post_patch_source(
            _make_strategy(), str(tmp_path), context, _make_slice_result(), conformance, patch,
        )
        attempt = result.attempts[0]
        assert attempt.success is True
        assert attempt.patch_ready is True
        assert attempt.resolved_target == "Policy.TARGET_CONST"
        assert attempt.target_start_line == 3 and attempt.target_end_line == 3
        assert attempt.start_line <= 3 <= attempt.end_line
        assert attempt.enclosing_symbol == "Policy"
        assert attempt.source_kind in ("enclosing_symbol", "patch_ready_window")
        assert attempt.identifier_verified_in_window is True


class TestSlice1To3AndRecommendationPolicyUnaffected:
    """Required regressions 11-12: this fix is scoped to Slice 4's own
    recovery-source construction only."""

    def test_slice_1_definition_context_lines_unchanged(self):
        """Test 11a. The narrow, evidence-sized padding Slices 1-3 share
        (build_final_target_slice's own category 2/constant reads) is
        untouched -- Slice 4's own, wider POST_PATCH_WINDOW_CONTEXT_LINES
        is a separate constant, never a redefinition of this one."""
        from utilities.autopatcher import remediation_planner as rp
        assert rp._DEFINITION_CONTEXT_LINES == 3
        assert rp.POST_PATCH_WINDOW_CONTEXT_LINES != rp._DEFINITION_CONTEXT_LINES

    def test_slice_1_to_3_functions_do_not_reference_new_post_patch_helpers(self):
        """Test 11b. build_final_target_slice, check_edit_readiness,
        run_deterministic_acquisition, and run_guided_acquisition (Slices
        1-3) never call any of the new Slice-4-only helpers -- this fix
        cannot have changed their behavior if their own source never
        mentions it."""
        import inspect
        from utilities.autopatcher import remediation_planner as rp

        new_names = (
            "_build_post_patch_window", "_PostPatchWindow", "_constant_group_bounds",
            "_locate_old_side_in_file", "_wrap_post_patch_window", "_window_confirms_target",
            "POST_PATCH_WINDOW_CONTEXT_LINES",
        )
        for fn in (
            rp.build_final_target_slice, rp.check_edit_readiness,
            rp.run_deterministic_acquisition, rp.run_guided_acquisition,
        ):
            source = inspect.getsource(fn)
            for name in new_names:
                assert name not in source, f"{name!r} leaked into {fn.__name__}"

    def test_slice_1_scenario_still_resolves_the_same_way(self, tmp_path):
        """Test 11c. A canonical Slice 1/2 scenario (unchanged from
        earlier regression coverage) still resolves identically."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_deterministic_acquisition,
        )
        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A"])
        edit = IntendedEdit(file="mod.py", symbol="mod.py:CONST_A")
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)
        assert initial_readiness.unready_edits[0].reason == "unresolved_symbol"

        result = run_deterministic_acquisition(strategy, str(tmp_path), context, initial_slice, initial_readiness)
        final_readiness = check_edit_readiness([edit], result.slice_result)
        assert final_readiness.edit_source_ready is True

    def test_recommendation_policy_unaffected(self):
        """Test 12. _build_recommendation_v1 never reads any Slice 4
        post-patch-recovery state, let alone this fix's own additions."""
        import inspect
        from utilities.autopatcher.pipeline import _build_recommendation_v1
        source = inspect.getsource(_build_recommendation_v1)
        for term in ("post_patch_recovery", "patch_ready", "post_patch_window", "recover_post_patch_source"):
            assert term not in source


class TestPatchReadyWindowIntegration:
    """Test 33 (generic, real-failure-shaped integration coverage): the
    exact failure shape the urllib3 trace proved -- a target constant
    sitting between two OTHER nearby constant definitions, with an
    initial patch whose old-side formatting/casing was wrong -- must now
    resolve to ONE contiguous window covering all three, letting a
    regenerated diff's context lines exist verbatim in the real file."""

    def test_scattered_constants_become_one_contiguous_patch_ready_window(self, tmp_path):
        from utilities.autopatcher.diff_hunk_repair import repair_hunk_headers
        from utilities.autopatcher.remediation_planner import (
            check_patch_target_conformance, post_patch_recovery_trigger_reasons,
            recover_post_patch_source,
        )

        # Generic shape: a status-codes definition, the actual target
        # constant, and a following constant -- all in one small class,
        # exactly like the real trace's RETRY_AFTER_STATUS_CODES /
        # DEFAULT_REMOVE_HEADERS_ON_REDIRECT / DEFAULT_BACKOFF_MAX triple.
        (tmp_path / "policy.py").write_text(
            "class Policy:\n"
            "    STATUS_CODES = frozenset([413, 429, 503])\n"
            "    TARGET_HEADERS = frozenset([\"Correct\"])\n"
            "    MAX_VALUE = 120\n",
            encoding="utf-8",
        )
        context = _make_context(constants={"policy.py": {
            "Policy.STATUS_CODES": {"qualified_name": "Policy.STATUS_CODES", "class_name": "Policy", "name": "STATUS_CODES", "line": 2, "end_line": 2},
            "Policy.TARGET_HEADERS": {"qualified_name": "Policy.TARGET_HEADERS", "class_name": "Policy", "name": "TARGET_HEADERS", "line": 3, "end_line": 3},
            "Policy.MAX_VALUE": {"qualified_name": "Policy.MAX_VALUE", "class_name": "Policy", "name": "MAX_VALUE", "line": 4, "end_line": 4},
        }}, repo_path=tmp_path)

        # Initial (hallucinated) patch: wrong old-side casing -- does not
        # match the real repository text, exactly like the real trace's
        # "authorization" -> "Authorization" mismatch.
        patch = (
            "--- a/policy.py\n+++ b/policy.py\n@@ -3,1 +3,1 @@\n"
            "-    TARGET_HEADERS = frozenset([\"correct\"])\n"
            "+    TARGET_HEADERS = frozenset([\"Correct\"])\n"
        )
        patch, meta = repair_hunk_headers(patch, repo_root=tmp_path)
        assert meta.relocations[0].relocation_reason == "no_match"

        slice_result = _make_slice_result()
        conformance = check_patch_target_conformance(patch, meta.relocations, [], slice_result)
        assert post_patch_recovery_trigger_reasons(conformance)

        strategy = _make_strategy(target_files=["policy.py"])
        result = recover_post_patch_source(strategy, str(tmp_path), context, slice_result, conformance, patch)

        assert result.ready_for_regeneration is True
        attempt = result.attempts[0]
        assert attempt.success is True
        assert attempt.patch_ready is True

        rendered = result.slice_result.rendered
        assert "STATUS_CODES" in rendered
        assert "TARGET_HEADERS" in rendered
        assert "MAX_VALUE" in rendered
        # ONE contiguous edit-target block -- not several independently
        # selected ones that merely happen to surround the target.
        assert rendered.count("#### Target definition:") == 1

        # The regenerated hunk's own context (the real, correctly-cased
        # line plus its immediate neighbors) now exists, verbatim and
        # uniquely, in the real repository file -- exactly what
        # content_relocation.find_unique_occurrence needs to relocate a
        # regenerated diff, unlike the original (hallucinated) old side.
        from utilities.autopatcher.content_relocation import find_unique_occurrence
        real_lines = (tmp_path / "policy.py").read_text(encoding="utf-8").splitlines()
        # find_unique_occurrence compares against whitespace-normalized
        # file lines (normalize_file_line strips each one) -- these
        # anchors are written the same, already-stripped way a real
        # hunk's own old_side_anchors() would produce them.
        regenerated_anchors = [
            "STATUS_CODES = frozenset([413, 429, 503])",
            "TARGET_HEADERS = frozenset([\"Correct\"])",
            "MAX_VALUE = 120",
        ]
        assert find_unique_occurrence(regenerated_anchors, real_lines) is not None


# ---------------------------------------------------------------------------
# Pipeline-level integration: call discipline, regeneration, trace, policy
# ---------------------------------------------------------------------------

class TestSlice4PipelineIntegration:
    """Tests 17-26, 30-33 -- exercised through the real pipeline.py wiring."""

    @staticmethod
    def _side_effect(stage_calls, patch_calls, bad_patch, good_patch, planning_target_files=None):
        # planning_target_files defaults to exactly the prior, hardcoded
        # ["mod.py"] -- every existing call site (which doesn't pass this
        # kwarg) sees byte-identical Target Discovery output to before.
        planning_target_files = list(planning_target_files) if planning_target_files is not None else ["mod.py"]

        def side_effect(system_prompt, user_message, stage="unknown"):
            stage_calls.append(stage)
            if stage == "remediation_planning":
                return json.dumps({
                    "remediation_mechanism": "fix it", "target_files": planning_target_files,
                    "target_symbols": [], "security_invariant": "stub", "required_edits": [],
                    "approaches_to_avoid": [], "explicit_unknowns": [],
                })
            if stage == "remediation_strategy":
                return json.dumps({
                    "extended_mechanism": None, "target_files": ["mod.py"],
                    "target_symbols": ["mod.py:CONST_A"], "required_edits": ["stub edit"],
                    "rejected_targets": [], "security_invariant": "stub", "insufficient_evidence": [],
                })
            return "{}"
        return side_effect

    def _run(self, tmp_path, bad_patch, good_patch, planning_target_files=None):
        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        # Present unconditionally so any fixture referencing these paths
        # in a hunk has a real, verifiable file to recover from/reject.
        for extra_name, extra_content in (("other.py", "X = 1\n"), ("yet_another.py", "Y = 1\n")):
            extra = tmp_path / extra_name
            if not extra.exists():
                extra.write_text(extra_content, encoding="utf-8")

        stage_calls: list = []
        patch_calls: list = []
        mock_llm = mock.MagicMock()
        mock_llm.complete.side_effect = self._side_effect(
            stage_calls, patch_calls, bad_patch, good_patch, planning_target_files=planning_target_files,
        )

        # Release: response-contract enforcement moved the initial
        # generation call site (Site 1) from generate_patch() to
        # _generate_patch_with_contract_check() -> generate_patch_raw()
        # (both defined in pipeline.py); Post-Patch Recovery's own
        # regeneration call (Site 3, what this test class exercises)
        # still calls generate_patch() directly (patch_generator.py),
        # unchanged. bad_patch is always Site 1's response and good_patch
        # is always Site 3's regeneration response in every caller of this
        # helper -- split into two single-purpose side effects (both still
        # appending to the same shared `patch_calls` list) rather than one
        # call-count-based function serving both.
        def _gen_patch_raw_side_effect(vulnerability_text, llm, code_context="", retry_hint="", stage="patch_generation"):
            patch_calls.append(retry_hint)
            return bad_patch

        def _gen_patch_side_effect(vulnerability_text, llm, code_context="", retry_hint=""):
            patch_calls.append(retry_hint)
            return good_patch

        # run() returns only the rendered Markdown report -- capture the
        # actual PipelineResult by wrapping the real _build_report (which
        # still runs normally, so the report/mocks below are unaffected).
        from utilities.autopatcher.pipeline import _build_report as _real_build_report
        captured: list = []

        def _capture_build_report(result):
            captured.append(result)
            return _real_build_report(result)

        with (
            mock.patch("utilities.autopatcher.pipeline.LLMClient", return_value=mock_llm),
            mock.patch("utilities.autopatcher.pipeline.generate_patch_raw", side_effect=_gen_patch_raw_side_effect),
            mock.patch("utilities.autopatcher.pipeline.generate_patch", side_effect=_gen_patch_side_effect) as mock_gen,
            mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="ok") as mock_review,
            mock.patch("utilities.autopatcher.pipeline.challenge_patch", return_value={}) as mock_challenge,
            mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="score: 7"),
            mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer"),
            mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
            mock.patch("utilities.autopatcher.pipeline._build_report", side_effect=_capture_build_report),
        ):
            from utilities.autopatcher.pipeline import run
            run("some vulnerability", api_key="", repo_root=str(tmp_path))
        result = captured[0]
        return result, stage_calls, patch_calls, mock_gen, mock_review, mock_challenge

    def test_valid_regenerated_patch_continues_through_existing_pipeline(self, tmp_path):
        """Test 30 + Test 22-24: a good regenerated patch is rechecked for
        conformance, then flows through applicability/challenger/reviewer
        exactly like any other patch. This test's own point is the
        DOWNSTREAM flow after a successful recovery+regeneration, not
        recovery eligibility itself -- other.py's recovery has always been
        expected to succeed here, which (post-eligibility) requires prior
        support. planning_target_files makes that pre-existing, implicit
        assumption explicit rather than changing what this test verifies."""
        bad_patch = "--- a/other.py\n+++ b/other.py\n@@ -1,1 +1,1 @@\n-X = 1\n+X = 2\n"
        good_patch = "--- a/mod.py\n+++ b/mod.py\n@@ -1,1 +1,1 @@\n-CONST_A = 1\n+CONST_A = 2\n"

        result, stage_calls, patch_calls, mock_gen, mock_review, mock_challenge = self._run(
            tmp_path, bad_patch, good_patch, planning_target_files=["mod.py", "other.py"],
        )

        assert mock_gen.call_count == 1  # Test 17: exactly one additional call
        assert result.patch_target_conformance is not None
        assert result.patch_target_conformance.all_conformant is True
        assert mock_review.called  # existing downstream stages still ran
        assert mock_challenge.called

    def test_regenerated_patch_reusing_recovered_file_present_in_target_discovery_is_accepted(self, tmp_path):
        """Test 4 (Issue 1 reconciliation + evidence-floor guard): the
        urllib3-shape scenario -- Target Discovery names BOTH mod.py and
        other.py; Final Strategy keeps only mod.py; Patch Generation edits
        other.py; Post-Patch Recovery verifies it (with a different,
        better symbol than anything named up front). Because other.py had
        prior support in Target Discovery, the second conformance check
        must accept it -- even though Final Strategy dropped it and no
        exact symbol inside it was ever named."""
        bad_patch = "--- a/other.py\n+++ b/other.py\n@@ -1,1 +1,1 @@\n-X = 1\n+X = 2\n"
        good_patch = "--- a/other.py\n+++ b/other.py\n@@ -1,1 +1,1 @@\n-X = 1\n+X = 99\n"
        (tmp_path / "other.py").write_text("X = 1\n", encoding="utf-8")

        result, _stage_calls, _patch_calls, mock_gen, mock_review, mock_challenge = self._run(
            tmp_path, bad_patch, good_patch, planning_target_files=["mod.py", "other.py"],
        )

        assert mock_gen.call_count == 1
        assert result.patch_target_conformance is not None
        assert result.patch_target_conformance.all_conformant is True
        assert not result.patch_target_conformance.unexpected_files
        assert result.patch is not None and result.patch.strip() != ""
        assert mock_review.called
        assert mock_challenge.called

    def test_regenerated_patch_reusing_file_absent_from_all_prior_evidence_still_fails_closed(self, tmp_path):
        """Test 5 (Issue 1 evidence-floor regression -> now enforced one
        step earlier, at recovery ELIGIBILITY): a file Patch Generation
        effectively invents -- never named by Target Discovery, Final
        Strategy, OR ReadyEdit -- must remain rejected. Before recovery
        eligibility existed, recovery would genuinely read real source
        for invented.py and only get rejected later, at promotion (the
        evidence-floor guard). Now the SAME safety property is enforced
        earlier and more cheaply: invented.py is not_recovery_eligible, so
        recovery fails it closed immediately, with NO retrieval attempted
        and NO regeneration call made at all -- there is no later
        promotion decision left to make. This is a stricter, not weaker,
        version of the original guarantee (still: Patch Generation can
        never launder a brand-new, zero-prior-evidence target through
        recovery)."""
        bad_patch = "--- a/invented.py\n+++ b/invented.py\n@@ -1,1 +1,1 @@\n-Z = 1\n+Z = 2\n"
        good_patch = "--- a/invented.py\n+++ b/invented.py\n@@ -1,1 +1,1 @@\n-Z = 1\n+Z = 99\n"
        (tmp_path / "invented.py").write_text("Z = 1\n", encoding="utf-8")

        result, _stage_calls, _patch_calls, mock_gen, _mock_review, _mock_challenge = self._run(
            tmp_path, bad_patch, good_patch,  # default planning_target_files == ["mod.py"] only
        )

        # Regeneration is never attempted -- recovery fails closed at the
        # eligibility gate, before generate_patch's one bounded retry call.
        assert mock_gen.call_count == 0
        assert result.post_patch_recovery is not None
        assert any(
            a.file == "invented.py" and a.success is False and a.failure_reason == "not_recovery_eligible"
            for a in result.post_patch_recovery.attempts
        )
        assert result.post_patch_recovery.ready_for_regeneration is False
        assert result.patch is None or result.patch == ""

    def test_planner_and_final_strategy_and_guided_acquisition_not_rerun(self, tmp_path):
        """Tests 18, 19, 20."""
        bad_patch = "--- a/other.py\n+++ b/other.py\n@@ -1,1 +1,1 @@\n-X = 1\n+X = 2\n"
        good_patch = "--- a/mod.py\n+++ b/mod.py\n@@ -1,1 +1,1 @@\n-CONST_A = 1\n+CONST_A = 2\n"
        (tmp_path / "other.py").write_text("X = 1\n", encoding="utf-8")

        _result, stage_calls, _patch_calls, _mock_gen, _mock_review, _mock_challenge = self._run(
            tmp_path, bad_patch, good_patch,
        )
        assert stage_calls.count("remediation_planning") == 1
        assert stage_calls.count("remediation_strategy") == 1
        assert "guided_context_request" not in stage_calls

    def test_regenerated_patch_with_no_match_fails_closed(self, tmp_path):
        """Test 25. The intent is the SECOND conformance check's own
        no_match handling (a regenerated patch whose content still can't
        be verified anywhere) -- that requires round-1 recovery for
        other.py to actually succeed first, so regeneration is attempted
        at all. planning_target_files gives other.py the prior support
        this test always implicitly relied on; without it, this test would
        instead exercise the (already separately covered) eligibility
        gate and never reach the no_match path it's named for."""
        bad_patch = "--- a/other.py\n+++ b/other.py\n@@ -1,1 +1,1 @@\n-X = 1\n+X = 2\n"
        # "Good" patch still can't be verified -- content never existed.
        still_bad_patch = "--- a/mod.py\n+++ b/mod.py\n@@ -1,1 +1,1 @@\n-NEVER_EXISTED = 1\n+NEVER_EXISTED = 2\n"
        (tmp_path / "other.py").write_text("X = 1\n", encoding="utf-8")

        result, _stage_calls, patch_calls, mock_gen, _mock_review, _mock_challenge = self._run(
            tmp_path, bad_patch, still_bad_patch, planning_target_files=["mod.py", "other.py"],
        )
        assert mock_gen.call_count == 1
        assert result.patch is None or result.patch == ""

    def test_regenerated_patch_with_new_unexpected_file_fails_closed(self, tmp_path):
        """Test 26. Same reasoning as test_regenerated_patch_with_no_match_
        fails_closed above: the intent is the SECOND conformance check
        rejecting a DIFFERENT unexpected file in the regenerated patch,
        which requires round-1 recovery for other.py to succeed first.
        planning_target_files makes that prior-support precondition
        explicit."""
        bad_patch = "--- a/other.py\n+++ b/other.py\n@@ -1,1 +1,1 @@\n-X = 1\n+X = 2\n"
        another_bad_patch = "--- a/yet_another.py\n+++ b/yet_another.py\n@@ -1,1 +1,1 @@\n-Y = 1\n+Y = 2\n"
        (tmp_path / "other.py").write_text("X = 1\n", encoding="utf-8")
        (tmp_path / "yet_another.py").write_text("Y = 1\n", encoding="utf-8")

        result, _stage_calls, _patch_calls, mock_gen, _mock_review, _mock_challenge = self._run(
            tmp_path, bad_patch, another_bad_patch, planning_target_files=["mod.py", "other.py"],
        )
        assert mock_gen.call_count == 1
        assert result.patch is None or result.patch == ""

    def test_empty_regenerated_diff_fails_closed(self, tmp_path):
        """Test 29. The intent is the empty/malformed-regenerated-diff
        branch, which is only reachable after round-1 recovery for
        other.py succeeds and generate_patch is actually called again.
        planning_target_files makes that always-implicit precondition
        explicit."""
        bad_patch = "--- a/other.py\n+++ b/other.py\n@@ -1,1 +1,1 @@\n-X = 1\n+X = 2\n"
        (tmp_path / "other.py").write_text("X = 1\n", encoding="utf-8")

        result, _stage_calls, _patch_calls, mock_gen, _mock_review, _mock_challenge = self._run(
            tmp_path, bad_patch, "", planning_target_files=["mod.py", "other.py"],
        )
        assert mock_gen.call_count == 1
        assert result.patch is None or result.patch == ""

    def test_recommendation_policy_unchanged(self):
        """Test 31. Also guards Issue 2's "No Patch Produced" execution
        outcome: that branching lives one level up in _build_report, never
        inside the Recommendation Policy function itself, which stays
        completely unaware of it."""
        import inspect
        from utilities.autopatcher.pipeline import _build_recommendation_v1
        source = inspect.getsource(_build_recommendation_v1)
        assert "patch_target_conformance" not in source
        assert "post_patch_recovery" not in source
        assert "no_patch" not in source
        assert "No Patch Produced" not in source

    def test_trace_artifact_emitted_when_recovery_runs(self, tmp_path, monkeypatch):
        """Test 32. The intent is the "regenerated_and_accepted" trace
        state, which is only reachable when round-1 recovery for other.py
        actually succeeds and regeneration is accepted end to end.
        planning_target_files gives other.py the prior support this test
        always implicitly relied on to reach that named state."""
        import json as _json
        bad_patch = "--- a/other.py\n+++ b/other.py\n@@ -1,1 +1,1 @@\n-X = 1\n+X = 2\n"
        good_patch = "--- a/mod.py\n+++ b/mod.py\n@@ -1,1 +1,1 @@\n-CONST_A = 1\n+CONST_A = 2\n"

        monkeypatch.setenv("AUTOPATCHER_DEBUG", "1")
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        monkeypatch.chdir(tmp_path)
        self._run(run_dir, bad_patch, good_patch, planning_target_files=["mod.py", "other.py"])

        files = list((tmp_path / "reports" / "debug").glob("post_patch_recovery_*.json"))
        assert len(files) == 1
        doc = _json.loads(files[0].read_text(encoding="utf-8"))
        assert doc["recovery_triggered"] is True
        assert doc["final_recovery_state"] == "regenerated_and_accepted"

    def test_trace_artifact_emitted_with_not_triggered_state_when_skipped(self, tmp_path, monkeypatch):
        """Test 33."""
        import json as _json
        good_patch = "--- a/mod.py\n+++ b/mod.py\n@@ -1,1 +1,1 @@\n-CONST_A = 1\n+CONST_A = 2\n"

        monkeypatch.setenv("AUTOPATCHER_DEBUG", "1")
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        monkeypatch.chdir(tmp_path)
        self._run(run_dir, good_patch, good_patch)

        files = list((tmp_path / "reports" / "debug").glob("post_patch_recovery_*.json"))
        assert len(files) == 1
        doc = _json.loads(files[0].read_text(encoding="utf-8"))
        assert doc["recovery_triggered"] is False
        assert doc["final_recovery_state"] == "not_triggered"


# ---------------------------------------------------------------------------
# build_post_patch_recovery_hint wording -- must accurately distinguish
# WHY recovery triggered rather than sharing one "could not be verified"
# claim across unexpected_file / uncovered_target / old_side_no_match.
# ---------------------------------------------------------------------------

class TestPostPatchRecoveryHintWording:
    def test_uncovered_target_wording_does_not_claim_unverified_source(self):
        """The real-world trigger this slice is meant to describe: the
        edited content WAS verified against the repository
        (old_side_status could be "old_side_verified"), but the edit
        fell outside the approved target -- the hint must say that, not
        the source-unverified claim that only applies to no_match."""
        from utilities.autopatcher.remediation_planner import (
            PatchConformanceReport, PostPatchRecoveryResult, build_post_patch_recovery_hint,
        )

        conformance = PatchConformanceReport(
            results=[], all_conformant=False, edited_files=["mod.py"],
            unexpected_files=[], uncovered_files=["mod.py"], no_match_files=[],
        )
        recovery = PostPatchRecoveryResult(
            triggered=True, trigger_reasons=["uncovered_target"], recovery_targets=["mod.py"],
            slice_result=None, attempts=[], ready_for_regeneration=True, failure_reason=None,
        )
        hint = build_post_patch_recovery_hint(conformance, recovery, "")
        assert "could not be verified" not in hint.lower()
        assert "mod.py" in hint
        assert "verified" in hint.lower() and "outside" in hint.lower()

    def test_unexpected_file_wording_still_names_unapproved_target(self):
        from utilities.autopatcher.remediation_planner import (
            PatchConformanceReport, PostPatchRecoveryResult, build_post_patch_recovery_hint,
        )

        conformance = PatchConformanceReport(
            results=[], all_conformant=False, edited_files=["other.py"],
            unexpected_files=["other.py"], uncovered_files=[], no_match_files=[],
        )
        recovery = PostPatchRecoveryResult(
            triggered=True, trigger_reasons=["unexpected_file"], recovery_targets=[],
            slice_result=None, attempts=[], ready_for_regeneration=False, failure_reason="too_many_recovery_targets",
        )
        hint = build_post_patch_recovery_hint(conformance, recovery, "")
        assert "other.py" in hint
        assert "not an approved edit target" in hint

    def test_no_match_wording_is_the_only_case_naming_unverified_content(self):
        """no_match is the one genuine "content could not be found/
        verified anywhere" case -- its own bullet keeps that wording;
        it must not also apply to the uncovered_target bullet (see
        test_uncovered_target_wording_does_not_claim_unverified_source)."""
        from utilities.autopatcher.remediation_planner import (
            PatchConformanceReport, PostPatchRecoveryResult, build_post_patch_recovery_hint,
        )

        conformance = PatchConformanceReport(
            results=[], all_conformant=False, edited_files=["mod.py"],
            unexpected_files=[], uncovered_files=[], no_match_files=["mod.py"],
        )
        recovery = PostPatchRecoveryResult(
            triggered=True, trigger_reasons=["old_side_no_match"], recovery_targets=["mod.py"],
            slice_result=None, attempts=[], ready_for_regeneration=True, failure_reason=None,
        )
        hint = build_post_patch_recovery_hint(conformance, recovery, "")
        assert "could not be found anywhere in the repository" in hint


# ---------------------------------------------------------------------------
# Genericity
# ---------------------------------------------------------------------------

class TestSlice4Genericity:
    def test_no_repository_specific_strings_in_slice_4_production_code(self):
        """Test 34. Scoped to Slice 4's own additions -- an unrelated,
        pre-existing docstring example from an earlier slice (e.g.
        _resolve_symbol_details' own urllib3 example, predating this
        slice) is out of this slice's scope to edit; this test verifies
        Slice 4 itself introduces none of these terms."""
        import pathlib
        forbidden = ["urllib3", "Cookie", "Retry", "PoolManager",
                     "DEFAULT_REMOVE_HEADERS_ON_REDIRECT", "CVE-2023-43804"]
        base = pathlib.Path(__file__).parent.parent.parent / "utilities" / "autopatcher"

        rp_text = (base / "remediation_planner.py").read_text(encoding="utf-8")
        marker = "# Slice 4 -- Post-Patch Target Conformance and Recovery"
        idx = rp_text.index(marker)
        slice_4_text = rp_text[idx:]
        for term in forbidden:
            assert term not in slice_4_text, f"{term!r} found in remediation_planner.py's Slice 4 section"

        pipeline_text = (base / "pipeline.py").read_text(encoding="utf-8")
        pipeline_start_marker = "# Slice 4 -- Patch Target Conformance Gate + Post-Patch Recovery"
        # Bounded to Slice 4's own inserted block only -- the very next
        # pre-existing section (hygiene/applicability/context reconstruction,
        # now routed through generated_patch_processing.process_generated_patch
        # -- see that extraction's own module docstring) immediately follows
        # it and must never be included here: it contains this pipeline's
        # own pre-existing, unrelated "applicability-aware retry"
        # terminology (plain English "retry", not urllib3's Retry class).
        pipeline_end_marker = "# Shared generated-diff mechanics"
        pidx = pipeline_text.index(pipeline_start_marker)
        eidx = pipeline_text.index(pipeline_end_marker, pidx)
        pipeline_slice_4_text = pipeline_text[pidx:eidx]
        for term in forbidden:
            assert term not in pipeline_slice_4_text, f"{term!r} found in pipeline.py's Slice 4 section"
