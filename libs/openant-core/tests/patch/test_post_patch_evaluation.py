"""Tests for post_patch_evaluation.evaluate_anchors (Phase 3: Post-Patch
Anchor Evaluation).

evaluate_anchors() is pure over two already-computed inputs (a list of
Anchor and an InvestigationContext | None), so every fixture here is built
purely in memory -- RepositoryIndex and ReachabilityAnalyzer both accept
plain dicts directly, with no file I/O -- exactly like Phase 2's tests.
"""

from __future__ import annotations

import copy
import inspect
from pathlib import Path
from unittest import mock

from utilities.agentic_enhancer.reachability_analyzer import ReachabilityAnalyzer
from utilities.agentic_enhancer.repository_index import RepositoryIndex
from utilities.autopatcher.candidate_enrichment import InvestigationContext
from utilities.autopatcher.post_patch_investigation import (
    Anchor,
    CallEdgeKey,
    ReachabilityKey,
    ReachabilityValue,
    ResolvedFunctionKey,
    ResolvedFunctionValue,
    SinkMatchKey,
    SinkMatchValue,
)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _function(func_id, start_line=1, end_line=5, name=None, unit_type="function", class_name=None):
    return {
        "id": func_id,
        "name": name or func_id.rsplit(":", 1)[-1],
        "startLine": start_line,
        "endLine": end_line,
        "unitType": unit_type,
        "className": class_name,
    }


def _context(functions, call_graph=None, reverse_call_graph=None, entry_points=None) -> InvestigationContext:
    index = RepositoryIndex({"functions": functions})
    reverse_call_graph = reverse_call_graph or {}
    entry_points = entry_points or set()
    reachability = ReachabilityAnalyzer(functions, reverse_call_graph, entry_points)
    return InvestigationContext(
        index=index,
        call_graph=call_graph or {},
        reverse_call_graph=reverse_call_graph,
        reachability=reachability,
    )


def _resolved_function_anchor(func_id, start_line=1, end_line=5, candidate_path="a.py", origin="pre_patch"):
    return Anchor(
        kind="resolved_function",
        candidate_path=candidate_path,
        key=ResolvedFunctionKey(func_id=func_id, name=func_id.rsplit(":", 1)[-1], class_name=None, unit_type="function"),
        before_value=ResolvedFunctionValue(start_line=start_line, end_line=end_line),
        source="candidate_enrichment.resolved_function",
        origin=origin,
    )


def _call_edge_anchor(caller_id, callee_id, candidate_path="a.py"):
    return Anchor(
        kind="call_edge",
        candidate_path=candidate_path,
        key=CallEdgeKey(caller_func_id=caller_id, callee_func_id=callee_id),
        before_value=True,
        source="candidate_enrichment.callees",
    )


def _reachability_anchor(func_id, reachable, entry_point_path=None, candidate_path="a.py"):
    return Anchor(
        kind="reachability",
        candidate_path=candidate_path,
        key=ReachabilityKey(func_id=func_id),
        before_value=ReachabilityValue(
            reachable=reachable,
            entry_point_path=tuple(entry_point_path) if entry_point_path else None,
        ),
        source="candidate_enrichment.is_reachable_from_entry_point",
    )


def _sink_match_anchor(candidate_path="a.py", method="run", line=10, snippet="os.system(x)"):
    return Anchor(
        kind="sink_match",
        candidate_path=candidate_path,
        key=SinkMatchKey(candidate_path=candidate_path, method=method),
        before_value=SinkMatchValue(line=line, snippet=snippet),
        source="candidate_enrichment.sink_matches",
    )


# ---------------------------------------------------------------------------
# resolved_function
# ---------------------------------------------------------------------------

class TestResolvedFunctionEvaluation:
    def test_unchanged(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        func_id = "a.py:foo"
        anchor = _resolved_function_anchor(func_id, start_line=1, end_line=5)
        context = _context({func_id: _function(func_id, start_line=1, end_line=5)})

        obs = evaluate_anchors([anchor], context)[0]
        assert obs.status == "unchanged"
        assert obs.after_value == ResolvedFunctionValue(start_line=1, end_line=5)
        assert obs.evaluated_via == "agentic_enhancer.repository_index.RepositoryIndex.get_function"

    def test_changed(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        func_id = "a.py:foo"
        anchor = _resolved_function_anchor(func_id, start_line=1, end_line=5)
        context = _context({func_id: _function(func_id, start_line=20, end_line=30)})

        obs = evaluate_anchors([anchor], context)[0]
        assert obs.status == "changed"
        assert obs.after_value == ResolvedFunctionValue(start_line=20, end_line=30)
        assert obs.before_value == ResolvedFunctionValue(start_line=1, end_line=5)

    def test_disappeared(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        anchor = _resolved_function_anchor("a.py:foo")
        context = _context({})  # func_id no longer present

        obs = evaluate_anchors([anchor], context)[0]
        assert obs.status == "disappeared"
        assert obs.after_value is None
        assert "no longer present" in obs.details

    def test_evaluation_error_on_unexpected_exception(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        anchor = _resolved_function_anchor("a.py:foo")
        broken_context = mock.MagicMock()
        broken_context.index.get_function.side_effect = RuntimeError("index corrupted")

        obs = evaluate_anchors([anchor], broken_context)[0]
        assert obs.status == "evaluation_error"
        assert obs.after_value is None
        assert "index corrupted" in obs.details


# ---------------------------------------------------------------------------
# call_edge
# ---------------------------------------------------------------------------

class TestCallEdgeEvaluation:
    def test_unchanged_when_edge_still_present(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        caller, callee = "a.py:foo", "b.py:bar"
        anchor = _call_edge_anchor(caller, callee)
        context = _context(
            {caller: _function(caller), callee: _function(callee)},
            call_graph={caller: [callee]},
        )

        obs = evaluate_anchors([anchor], context)[0]
        assert obs.status == "unchanged"
        assert obs.after_value is True

    def test_disappeared_when_caller_no_longer_calls_callee(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        caller, callee = "a.py:foo", "b.py:bar"
        anchor = _call_edge_anchor(caller, callee)
        context = _context(
            {caller: _function(caller), callee: _function(callee)},
            call_graph={caller: []},  # caller exists but no longer calls callee
        )

        obs = evaluate_anchors([anchor], context)[0]
        assert obs.status == "disappeared"
        assert obs.after_value is False

    def test_unresolved_when_caller_no_longer_resolves(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        anchor = _call_edge_anchor("a.py:foo", "b.py:bar")
        context = _context({})  # caller itself is gone

        obs = evaluate_anchors([anchor], context)[0]
        assert obs.status == "unresolved"
        assert obs.after_value is None


# ---------------------------------------------------------------------------
# reachability
# ---------------------------------------------------------------------------

class TestReachabilityEvaluation:
    def test_unchanged(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        func_id, entry_id = "a.py:foo", "entry.py:main"
        anchor = _reachability_anchor(func_id, reachable=True, entry_point_path=[entry_id, func_id])
        context = _context(
            {func_id: _function(func_id), entry_id: _function(entry_id)},
            reverse_call_graph={func_id: [entry_id]},
            entry_points={entry_id},
        )

        obs = evaluate_anchors([anchor], context)[0]
        assert obs.status == "unchanged"
        assert obs.after_value.reachable is True

    def test_changed_true_to_false(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        func_id = "a.py:foo"
        anchor = _reachability_anchor(func_id, reachable=True, entry_point_path=["entry.py:main", func_id])
        context = _context({func_id: _function(func_id)})  # no reverse edges, no entry points -> unreachable now

        obs = evaluate_anchors([anchor], context)[0]
        assert obs.status == "changed"
        assert obs.after_value.reachable is False
        assert obs.after_value.entry_point_path is None

    def test_changed_when_previously_unresolved(self):
        """before_value.reachable is None (a rare pre-patch
        enrichment-exception state) transitioning to a definite value is a
        known/unknown transition, not a presence/absence one -- reported
        as `changed`, the same as any other value difference, not a
        dedicated status."""
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        func_id, entry_id = "a.py:foo", "entry.py:main"
        anchor = _reachability_anchor(func_id, reachable=None, entry_point_path=None)
        context = _context(
            {func_id: _function(func_id), entry_id: _function(entry_id)},
            reverse_call_graph={func_id: [entry_id]},
            entry_points={entry_id},
        )

        obs = evaluate_anchors([anchor], context)[0]
        assert obs.status == "changed"
        assert obs.after_value.reachable is True

    def test_unresolved_when_function_gone(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        anchor = _reachability_anchor("a.py:foo", reachable=True, entry_point_path=["entry.py:main", "a.py:foo"])
        context = _context({})

        obs = evaluate_anchors([anchor], context)[0]
        assert obs.status == "unresolved"
        assert obs.after_value is None

    def test_evaluation_error_on_unexpected_exception(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        func_id = "a.py:foo"
        anchor = _reachability_anchor(func_id, reachable=True)
        broken_context = mock.MagicMock()
        broken_context.index.get_function.return_value = _function(func_id)
        broken_context.reachability.is_reachable_from_entry_point.side_effect = RuntimeError("bfs exploded")

        obs = evaluate_anchors([anchor], broken_context)[0]
        assert obs.status == "evaluation_error"
        assert "bfs exploded" in obs.details


# ---------------------------------------------------------------------------
# constant_value
# ---------------------------------------------------------------------------

def _constant_context(functions=None, constants=None) -> InvestigationContext:
    functions = functions or {}
    return InvestigationContext(
        index=RepositoryIndex({"functions": functions}),
        call_graph={},
        reverse_call_graph={},
        reachability=ReachabilityAnalyzer(functions, {}, set()),
        constants=constants or {},
    )


def _constant_value_anchor(candidate_path, qualified_name, class_name, kind, value, origin="pre_patch"):
    from utilities.autopatcher.post_patch_investigation import ConstantValueKey, ConstantValueValue

    return Anchor(
        kind="constant_value",
        candidate_path=candidate_path,
        key=ConstantValueKey(
            const_id=f"{candidate_path}:{qualified_name}", qualified_name=qualified_name, class_name=class_name,
        ),
        before_value=ConstantValueValue(ast_literal_kind=kind, value=value),
        source="candidate_enrichment.scope_constants",
        origin=origin,
    )


def _constant_entry(qualified_name, class_name, name, outcome="literal", kind="frozenset_call", value=None, line=1, end_line=1):
    return {
        "qualified_name": qualified_name, "class_name": class_name, "name": name,
        "outcome": outcome, "ast_literal_kind": kind, "value": value, "line": line, "end_line": end_line,
    }


class TestConstantValueEvaluation:
    def test_unchanged(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        anchor = _constant_value_anchor("retry.py", "Retry.X", "Retry", "frozenset_call", frozenset({"Authorization"}))
        context = _constant_context(constants={
            "retry.py": {"Retry.X": _constant_entry("Retry.X", "Retry", "X", value=frozenset({"Authorization"}))}
        })

        obs = evaluate_anchors([anchor], context)[0]
        assert obs.status == "unchanged"
        assert obs.after_value.value == frozenset({"Authorization"})
        assert obs.evaluated_via == "candidate_enrichment.InvestigationContext.constants"

    def test_changed_detects_the_actual_cve_2023_43804_fix(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        anchor = _constant_value_anchor(
            "retry.py", "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT", "Retry",
            "frozenset_call", frozenset({"Authorization"}),
        )
        context = _constant_context(constants={
            "retry.py": {"Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT": _constant_entry(
                "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT", "Retry", "DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
                value=frozenset({"Authorization", "Cookie"}),
            )}
        })

        obs = evaluate_anchors([anchor], context)[0]
        assert obs.status == "changed"
        assert obs.before_value.value == frozenset({"Authorization"})
        assert obs.after_value.value == frozenset({"Authorization", "Cookie"})

    def test_disappeared_when_target_no_longer_found(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        anchor = _constant_value_anchor("a.py", "X", None, "Constant", 30)
        context = _constant_context(constants={})

        obs = evaluate_anchors([anchor], context)[0]
        assert obs.status == "disappeared"
        assert obs.after_value is None

    def test_unresolved_when_now_non_literal(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        anchor = _constant_value_anchor("a.py", "BACKEND", None, "Call", "default_backend")
        context = _constant_context(constants={
            "a.py": {"BACKEND": _constant_entry("BACKEND", None, "BACKEND", outcome="non_literal", kind=None, value=None)}
        })

        obs = evaluate_anchors([anchor], context)[0]
        assert obs.status == "unresolved"
        assert "non_literal" in obs.details

    def test_evaluation_error_becomes_evaluation_error_status_when_no_context(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        anchor = _constant_value_anchor("a.py", "X", None, "Constant", 1)
        observations = evaluate_anchors([anchor], None)
        assert observations[0].status == "evaluation_error"


# ---------------------------------------------------------------------------
# origin: pre_patch (default) vs patch_touched -- mechanical propagation only,
# never a branch in evaluation logic itself.
# ---------------------------------------------------------------------------

class TestAnchorOriginPropagation:
    def test_default_origin_is_pre_patch(self):
        anchor = _resolved_function_anchor("a.py:foo")
        assert anchor.origin == "pre_patch"

    def test_observation_echoes_the_anchors_origin(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        func_id = "a.py:foo"
        pre_patch = _resolved_function_anchor(func_id, origin="pre_patch")
        patch_touched = _resolved_function_anchor("b.py:bar", origin="patch_touched")
        context = _context({func_id: _function(func_id), "b.py:bar": _function("b.py:bar")})

        observations = evaluate_anchors([pre_patch, patch_touched], context)
        by_kind_key = {(o.anchor_key.func_id): o for o in observations}
        assert by_kind_key[func_id].origin == "pre_patch"
        assert by_kind_key["b.py:bar"].origin == "patch_touched"

    def test_origin_never_changes_evaluated_status_or_after_value(self):
        """Two anchors identical except for origin must evaluate
        identically in every other respect -- proves evaluate_anchors()
        does not branch on origin, it only carries it through."""
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        func_id = "a.py:foo"
        pre_patch = _resolved_function_anchor(func_id, start_line=1, end_line=5, origin="pre_patch")
        patch_touched = _resolved_function_anchor(func_id, start_line=1, end_line=5, origin="patch_touched")
        context = _context({func_id: _function(func_id, start_line=20, end_line=30)})

        obs_pre, obs_patch = evaluate_anchors([pre_patch, patch_touched], context)
        assert obs_pre.status == obs_patch.status == "changed"
        assert obs_pre.after_value == obs_patch.after_value
        assert obs_pre.evaluated_via == obs_patch.evaluated_via
        assert obs_pre.origin == "pre_patch"
        assert obs_patch.origin == "patch_touched"

    def test_origin_defaults_on_constant_value_and_evaluation_error_paths_too(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        anchor = _constant_value_anchor("a.py", "X", None, "Constant", 1, origin="patch_touched")
        observations = evaluate_anchors([anchor], None)  # no context -> evaluation_error
        assert observations[0].status == "evaluation_error"
        assert observations[0].origin == "patch_touched"


# ---------------------------------------------------------------------------
# sink_match -- deferred, always unresolved
# ---------------------------------------------------------------------------

class TestSinkMatchDeferred:
    def test_always_unresolved_regardless_of_context(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        anchor = _sink_match_anchor()
        context = _context({"a.py:run": _function("a.py:run")})

        obs = evaluate_anchors([anchor], context)[0]
        assert obs.status == "unresolved"
        assert "deferred" in obs.details
        assert obs.evaluated_via == "deferred"

    def test_unresolved_even_with_no_context(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        anchor = _sink_match_anchor()
        obs = evaluate_anchors([anchor], None)[0]
        assert obs.status == "unresolved"

    def test_details_are_user_facing_not_implementation_internal(self):
        """Release-polish (Decision 6): the customer-facing note must not
        leak implementation-internal identifiers/phrasing (Anchor,
        evaluate_anchors(), vuln_class, anchor-derivation time, future
        evaluation path) while still preserving uncertainty -- it must not
        read as a completed or successful check."""
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        anchor = _sink_match_anchor()
        obs = evaluate_anchors([anchor], None)[0]
        for jargon in (
            "vuln_class", "Anchor", "evaluate_anchors()",
            "anchor-derivation", "future evaluation path",
        ):
            assert jargon not in obs.details
        assert obs.status == "unresolved"
        assert "not independently re-checked" in obs.details


# ---------------------------------------------------------------------------
# Missing context
# ---------------------------------------------------------------------------

class TestMissingContext:
    def test_context_dependent_kinds_become_evaluation_error(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        anchors = [
            _resolved_function_anchor("a.py:foo"),
            _call_edge_anchor("a.py:foo", "b.py:bar"),
            _reachability_anchor("a.py:foo", reachable=True),
            _constant_value_anchor("a.py", "X", None, "Constant", 1),
        ]
        observations = evaluate_anchors(anchors, None)
        assert all(o.status == "evaluation_error" for o in observations)
        assert all(o.after_value is None for o in observations)


# ---------------------------------------------------------------------------
# Ordering, provenance, determinism, purity
# ---------------------------------------------------------------------------

class TestOrderingAndProvenance:
    def test_ordering_preserved_across_mixed_kinds(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        func_id = "a.py:foo"
        anchors = [
            _sink_match_anchor(),
            _resolved_function_anchor(func_id),
            _call_edge_anchor(func_id, "b.py:bar"),
            _reachability_anchor(func_id, reachable=True),
        ]
        context = _context({func_id: _function(func_id)})

        observations = evaluate_anchors(anchors, context)
        assert [o.anchor_kind for o in observations] == [a.kind for a in anchors]
        assert [o.anchor_key for o in observations] == [a.key for a in anchors]

    def test_provenance_preserved(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        func_id = "a.py:foo"
        anchor = _resolved_function_anchor(func_id)
        context = _context({func_id: _function(func_id)})

        obs = evaluate_anchors([anchor], context)[0]
        assert obs.anchor_kind == anchor.kind
        assert obs.anchor_key == anchor.key
        assert obs.candidate_path == anchor.candidate_path
        assert obs.source == anchor.source
        assert obs.evaluated_via == "agentic_enhancer.repository_index.RepositoryIndex.get_function"


class TestDeterminismAndPurity:
    def test_repeated_evaluation_is_deterministic(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        func_id = "a.py:foo"
        anchors = [_resolved_function_anchor(func_id), _reachability_anchor(func_id, reachable=True)]
        context = _context({func_id: _function(func_id)})

        result1 = evaluate_anchors(anchors, context)
        result2 = evaluate_anchors(anchors, context)
        assert result1 == result2

    def test_no_mutation_of_anchors_or_context(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        func_id = "a.py:foo"
        anchors = [_resolved_function_anchor(func_id, start_line=1, end_line=5)]
        context = _context({func_id: _function(func_id, start_line=1, end_line=5)})
        anchors_snapshot = copy.deepcopy(anchors)

        evaluate_anchors(anchors, context)

        assert anchors == anchors_snapshot
        assert context.index.get_function(func_id) == _function(func_id, start_line=1, end_line=5)

    def test_empty_anchors_returns_empty_list(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        assert evaluate_anchors([], None) == []
        assert evaluate_anchors([], _context({})) == []

    def test_no_disallowed_imports(self):
        import utilities.autopatcher.post_patch_evaluation as mod

        source = inspect.getsource(mod)
        disallowed = [
            "import subprocess", "import socket", "import requests",
            "import tempfile", "import shutil",
            "anthropic", "openai", "urllib",
        ]
        for token in disallowed:
            assert token not in source, f"unexpected token found: {token}"

    def test_no_recommendation_or_verdict_vocabulary(self):
        """#16: statuses and details must never read as a recommendation --
        only comparison-neutral facts."""
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        func_id = "a.py:foo"
        anchors = [
            _resolved_function_anchor(func_id),
            _call_edge_anchor(func_id, "b.py:bar"),
            _reachability_anchor(func_id, reachable=True),
            _sink_match_anchor(),
        ]
        context = _context({})  # force every branch to produce a details string

        observations = evaluate_anchors(anchors, context)
        blocklist = ["fixed", "correct", "success", "vulnerable", "safe", "remediat"]
        for obs in observations:
            text = (obs.details or "").lower()
            for word in blocklist:
                assert word not in text, f"{word!r} found in details: {text!r}"


# ---------------------------------------------------------------------------
# render_post_patch_investigation
# ---------------------------------------------------------------------------

def _diff(file_path, before_lines, after_lines, start=1):
    """Minimal unified-diff builder covering exactly what diff_parsing.parse_diff
    understands: '--- a/', '+++ b/', an '@@ ... +start,count @@' header, and
    ' '/'+'/'-' body lines. Produces one hunk with every before-line removed
    and every after-line added (a full-file replace) -- simple and sufficient
    for these tests, which only care about symbol attribution, not minimal diffs."""
    count = max(len(before_lines), len(after_lines))
    lines = [f"--- a/{file_path}", f"+++ b/{file_path}", f"@@ -{start},{len(before_lines)} +{start},{count} @@"]
    lines += [f"-{l}" for l in before_lines]
    lines += [f"+{l}" for l in after_lines]
    return "\n".join(lines) + "\n"


class TestComputeCoverage:
    def test_returns_none_without_a_context(self):
        from utilities.autopatcher.post_patch_evaluation import compute_coverage

        assert compute_coverage("--- a/x.py\n+++ b/x.py\n", [], Path("/nonexistent"), None) is None

    def test_treats_pre_patch_and_patch_touched_origins_equally(self, tmp_path):
        """Explicit requirement: coverage accounting must not care which
        phase produced the covering Anchor."""
        from utilities.autopatcher.post_patch_evaluation import compute_coverage

        (tmp_path / "a.py").write_text("def foo():\n    return 1\n", encoding="utf-8")
        diff = _diff("a.py", ["    return 1"], ["    return 2"], start=2)
        func_id = "a.py:foo"
        context = _constant_context(functions={func_id: _function(func_id, start_line=1, end_line=2)})

        pre_patch_result = compute_coverage(
            diff, [_resolved_function_anchor(func_id, start_line=1, end_line=2, origin="pre_patch")], tmp_path, context,
        )
        patch_touched_result = compute_coverage(
            diff, [_resolved_function_anchor(func_id, start_line=1, end_line=2, origin="patch_touched")], tmp_path, context,
        )
        assert pre_patch_result.covered == patch_touched_result.covered == (func_id,)
        assert pre_patch_result.uncovered == patch_touched_result.uncovered == ()

    def test_covered_element_matches_a_resolved_function_anchor(self, tmp_path):
        from utilities.autopatcher.post_patch_evaluation import compute_coverage

        (tmp_path / "a.py").write_text("def foo():\n    return 1\n", encoding="utf-8")
        diff = _diff("a.py", ["    return 1"], ["    return 2"], start=2)
        func_id = "a.py:foo"
        anchors = [_resolved_function_anchor(func_id, start_line=1, end_line=2, candidate_path="a.py")]
        context = _constant_context(functions={func_id: _function(func_id, start_line=1, end_line=2)})

        result = compute_coverage(diff, anchors, tmp_path, context)
        assert result.total == 1
        assert result.covered == (func_id,)
        assert result.uncovered == ()

    def test_uncovered_element_when_no_anchor_names_it(self, tmp_path):
        """The CVE-2023-43804 shape before constant_value anchors exist:
        the diff touches a class constant, but only resolved_function
        anchors exist -- must report uncovered, never fabricate coverage."""
        from utilities.autopatcher.post_patch_evaluation import compute_coverage

        (tmp_path / "retry.py").write_text(
            "class Retry:\n    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset([\"Authorization\"])\n",
            encoding="utf-8",
        )
        diff = _diff(
            "retry.py",
            ['    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])'],
            ['    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Cookie", "Authorization"])'],
            start=2,
        )
        # The element is resolvable (it's a known constant, on line 2 of
        # the file) -- but no Anchor names it, since anchors=[] below.
        context = _constant_context(constants={
            "retry.py": {"Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT": _constant_entry(
                "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT", "Retry", "DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
                value=frozenset({"Authorization"}),
                line=2, end_line=2,
            )}
        })
        result = compute_coverage(diff, anchors=[], repo_root=tmp_path, context=context)
        assert result.total == 1
        assert result.covered == ()
        assert len(result.uncovered) == 1
        assert "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT" in result.uncovered[0]

    def test_covered_once_constant_value_anchor_exists(self, tmp_path):
        """Same diff as above, but now a constant_value anchor exists for
        the touched constant -- must report covered."""
        from utilities.autopatcher.post_patch_evaluation import compute_coverage

        (tmp_path / "retry.py").write_text(
            "class Retry:\n    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset([\"Authorization\"])\n",
            encoding="utf-8",
        )
        diff = _diff(
            "retry.py",
            ['    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])'],
            ['    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Cookie", "Authorization"])'],
            start=2,
        )
        anchors = [_constant_value_anchor(
            "retry.py", "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT", "Retry", "frozenset_call", frozenset({"Authorization"}),
        )]
        context = _constant_context(
            functions={},
            constants={"retry.py": {"Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT": _constant_entry(
                "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT", "Retry", "DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
                value=frozenset({"Authorization"}),
                line=2, end_line=2,
            )}},
        )
        result = compute_coverage(diff, anchors, tmp_path, context)
        assert result.total == 1
        assert len(result.covered) == 1
        assert "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT" in result.covered[0]
        assert result.uncovered == ()

    def test_unreadable_file_counts_as_unattributed_not_dropped(self, tmp_path):
        from utilities.autopatcher.post_patch_evaluation import compute_coverage

        diff = _diff("missing.py", ["x = 1"], ["x = 2"])
        context = _constant_context()
        result = compute_coverage(diff, [], tmp_path, context)
        assert result.total == 0
        assert result.unattributed == 1

    def test_call_edge_anchors_never_credited_as_coverage(self, tmp_path):
        """call_edge's key names a relationship between two OTHER
        locations, not an observable property of the touched location's
        own content -- must never manufacture false coverage."""
        from utilities.autopatcher.post_patch_evaluation import compute_coverage

        (tmp_path / "a.py").write_text("def foo():\n    return 1\n", encoding="utf-8")
        diff = _diff("a.py", ["    return 1"], ["    return 2"], start=2)
        anchors = [_call_edge_anchor("a.py:foo", "b.py:bar", candidate_path="a.py")]
        context = _constant_context(functions={"a.py:foo": _function("a.py:foo", start_line=1, end_line=2)})

        result = compute_coverage(diff, anchors, tmp_path, context)
        assert result.covered == ()
        assert result.uncovered == ("a.py:foo",)


class TestDerivePatchTouchedAnchors:
    """derive_patch_touched_anchors -- the candidate-selection-independent
    fix: resolves the final patch's own diff directly against the
    pre-patch InvestigationContext, never against selected candidates."""

    def test_returns_empty_list_without_a_context(self):
        from utilities.autopatcher.post_patch_evaluation import derive_patch_touched_anchors

        assert derive_patch_touched_anchors("--- a/x.py\n+++ b/x.py\n", Path("/nonexistent"), None, []) == []

    def test_derives_a_new_constant_value_anchor_for_the_cve_2023_43804_shape(self, tmp_path):
        """The exact motivating scenario: retry.py was never a selected
        candidate (existing_anchors has nothing for it), but the final
        patch touches Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT -- must
        derive a fresh, origin="patch_touched" Anchor for it."""
        from utilities.autopatcher.post_patch_evaluation import derive_patch_touched_anchors

        (tmp_path / "retry.py").write_text(
            "class Retry:\n    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset([\"Authorization\"])\n",
            encoding="utf-8",
        )
        diff = _diff(
            "retry.py",
            ['    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])'],
            ['    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Cookie", "Authorization"])'],
            start=2,
        )
        context = _constant_context(constants={
            "retry.py": {"Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT": _constant_entry(
                "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT", "Retry", "DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
                value=frozenset({"Authorization"}), line=2, end_line=2,
            )}
        })

        derived = derive_patch_touched_anchors(diff, tmp_path, context, existing_anchors=[])
        assert len(derived) == 1
        anchor = derived[0]
        assert anchor.kind == "constant_value"
        assert anchor.origin == "patch_touched"
        assert anchor.key.qualified_name == "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT"
        assert anchor.before_value.value == frozenset({"Authorization"})

    def test_skips_a_ref_already_covered_by_an_existing_anchor(self, tmp_path):
        """No duplicate anchor when the file WAS a selected candidate and
        already has an anchor for this exact element."""
        from utilities.autopatcher.post_patch_evaluation import derive_patch_touched_anchors

        (tmp_path / "a.py").write_text("def foo():\n    return 1\n", encoding="utf-8")
        diff = _diff("a.py", ["    return 1"], ["    return 2"], start=2)
        existing = [_resolved_function_anchor("a.py:foo", start_line=1, end_line=2, candidate_path="a.py")]
        context = _constant_context(functions={"a.py:foo": _function("a.py:foo", start_line=1, end_line=2)})

        derived = derive_patch_touched_anchors(diff, tmp_path, context, existing_anchors=existing)
        assert derived == []

    def test_skips_module_level_fallback_matches(self, tmp_path):
        """A hunk resolving only to the whole-file module_level catch-all
        unit carries no meaningful signal -- must never fabricate a
        near-content-free resolved_function anchor for it (it should
        render as uncovered via Coverage Analysis instead)."""
        from utilities.autopatcher.post_patch_evaluation import derive_patch_touched_anchors

        (tmp_path / "a.py").write_text("x = 1\ny = 2\n", encoding="utf-8")
        diff = _diff("a.py", ["x = 1"], ["x = 100"], start=1)
        context = _constant_context(functions={
            "a.py:__module__": _function("a.py:__module__", start_line=1, end_line=2, unit_type="module_level"),
        })

        derived = derive_patch_touched_anchors(diff, tmp_path, context, existing_anchors=[])
        assert derived == []

    def test_skips_non_literal_constants(self, tmp_path):
        """No fabricated value for a constant whose RHS isn't a
        supported literal shape."""
        from utilities.autopatcher.post_patch_evaluation import derive_patch_touched_anchors

        (tmp_path / "a.py").write_text("BACKEND = default_backend()\n", encoding="utf-8")
        diff = _diff("a.py", ["BACKEND = default_backend()"], ["BACKEND = other_backend()"], start=1)
        context = _constant_context(constants={
            "a.py": {"BACKEND": _constant_entry("BACKEND", None, "BACKEND", outcome="non_literal", kind=None, value=None)}
        })

        derived = derive_patch_touched_anchors(diff, tmp_path, context, existing_anchors=[])
        assert derived == []

    def test_deduplicates_multiple_hunks_resolving_to_the_same_element(self, tmp_path):
        from utilities.autopatcher.post_patch_evaluation import derive_patch_touched_anchors

        (tmp_path / "a.py").write_text("def foo():\n    x = 1\n    return x\n", encoding="utf-8")
        diff = (
            "--- a/a.py\n+++ b/a.py\n@@ -1,3 +1,3 @@\n"
            " def foo():\n-    x = 1\n+    x = 2\n-    return x\n+    return x + 1\n"
        )
        context = _constant_context(functions={"a.py:foo": _function("a.py:foo", start_line=1, end_line=3)})

        derived = derive_patch_touched_anchors(diff, tmp_path, context, existing_anchors=[])
        assert len(derived) == 1

    def test_new_anchors_only_never_returns_existing_anchors_object(self, tmp_path):
        """Contract: existing_anchors is read for identity comparison only,
        never mutated, never echoed back."""
        from utilities.autopatcher.post_patch_evaluation import derive_patch_touched_anchors

        (tmp_path / "retry.py").write_text(
            "class Retry:\n    X = frozenset([\"A\"])\n", encoding="utf-8",
        )
        diff = _diff("retry.py", ['    X = frozenset(["A"])'], ['    X = frozenset(["A", "B"])'], start=2)
        context = _constant_context(constants={
            "retry.py": {"Retry.X": _constant_entry("Retry.X", "Retry", "X", value=frozenset({"A"}), line=2, end_line=2)}
        })
        existing = [_resolved_function_anchor("unrelated.py:bar")]
        snapshot = list(existing)

        derived = derive_patch_touched_anchors(diff, tmp_path, context, existing_anchors=existing)
        assert existing == snapshot
        assert all(a not in existing for a in derived)


class TestRenderPostPatchInvestigation:
    def test_empty_observations(self):
        from utilities.autopatcher.post_patch_evaluation import render_post_patch_investigation

        rendered = render_post_patch_investigation([])
        assert rendered.startswith("## Post-Patch Investigation")
        assert "No anchors were available to re-evaluate." in rendered

    def test_grouped_by_status(self):
        from utilities.autopatcher.post_patch_evaluation import (
            AnchorObservation, render_post_patch_investigation,
        )

        def _obs(status, kind="resolved_function", details=None):
            return AnchorObservation(
                anchor_kind=kind,
                anchor_key=ResolvedFunctionKey(func_id="a.py:foo", name="foo", class_name=None, unit_type="function"),
                candidate_path="a.py",
                status=status,
                before_value=ResolvedFunctionValue(start_line=1, end_line=5),
                after_value=ResolvedFunctionValue(start_line=1, end_line=9) if status == "changed" else None,
                details=details,
                source="candidate_enrichment.resolved_function",
                evaluated_via="agentic_enhancer.repository_index.RepositoryIndex.get_function",
            )

        observations = [
            _obs("changed"),
            _obs("disappeared", details="function id no longer present in the patched copy"),
            _obs("unchanged"),
            _obs("unresolved", details="function id no longer resolves in the patched copy"),
            _obs("evaluation_error", details="lookup failed: RuntimeError: boom"),
        ]
        rendered = render_post_patch_investigation(observations)

        assert "### Changed" in rendered
        assert "### Disappeared" in rendered
        assert "### Unchanged" in rendered
        assert "### Remaining Unknowns" in rendered
        # Changed/Disappeared content appears under their own headings.
        changed_idx = rendered.index("### Changed")
        disappeared_idx = rendered.index("### Disappeared")
        unchanged_idx = rendered.index("### Unchanged")
        unknowns_idx = rendered.index("### Remaining Unknowns")
        assert changed_idx < disappeared_idx < unchanged_idx < unknowns_idx
        assert "resolved_function:a.py:foo" in rendered[changed_idx:disappeared_idx]
        assert "no longer present" in rendered[disappeared_idx:unchanged_idx]
        assert "1 anchor(s) confirmed unchanged" in rendered[unchanged_idx:unknowns_idx]
        # Both unresolved and evaluation_error land in Remaining Unknowns, never elsewhere.
        unknowns_section = rendered[unknowns_idx:]
        assert "unresolved" in unknowns_section
        assert "evaluation_error" in unknowns_section

    def test_sink_match_always_lands_in_remaining_unknowns(self):
        """sink_match is always status='unresolved' today (Phase 3 defers
        it) -- confirms it's never miscategorized into a determinate group."""
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors, render_post_patch_investigation

        anchors = [_sink_match_anchor()]
        observations = evaluate_anchors(anchors, None)
        rendered = render_post_patch_investigation(observations)

        assert "### Remaining Unknowns" in rendered
        unknowns_idx = rendered.index("### Remaining Unknowns")
        assert "sink_match" in rendered[unknowns_idx:]
        # Never appears in the determinate-looking sections above.
        assert "sink_match" not in rendered[:rendered.index("### Changed")]

    def test_never_mutates_input(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors, render_post_patch_investigation

        func_id = "a.py:foo"
        anchors = [_resolved_function_anchor(func_id)]
        context = _context({func_id: _function(func_id)})
        observations = evaluate_anchors(anchors, context)
        snapshot = list(observations)

        render_post_patch_investigation(observations)

        assert observations == snapshot

    def test_never_exceeds_max_chars(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors, render_post_patch_investigation

        anchors = [
            _resolved_function_anchor(f"a{i}.py:foo", candidate_path=f"a{i}.py")
            for i in range(50)
        ]
        context = _context({})  # everything -> disappeared, exercises the per-group item cap
        observations = evaluate_anchors(anchors, context)

        rendered = render_post_patch_investigation(observations, max_chars=500)
        assert len(rendered) <= 500
        assert "(+" in rendered or "truncated" in rendered

    def test_no_recommendation_or_verdict_vocabulary_in_data_sections(self):
        """The blocklist applies to the data-driven sections (Changed/
        Disappeared/Unchanged/Remaining Unknowns), not the fixed preamble
        -- which legitimately says "not a verdict that the patch is
        correct... or a successful fix" to explicitly disclaim exactly
        those words, the same way evidence_fusion.py's own preamble does."""
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors, render_post_patch_investigation

        func_id = "a.py:foo"
        anchors = [
            _resolved_function_anchor(func_id),
            _call_edge_anchor(func_id, "b.py:bar"),
            _reachability_anchor(func_id, reachable=True),
            _sink_match_anchor(),
        ]
        context = _context({})
        rendered = render_post_patch_investigation(evaluate_anchors(anchors, context))

        data_sections = rendered[rendered.index("### Changed"):]
        blocklist = ["fixed", "correct", "success", "vulnerable", "safe", "remediat"]
        lowered = data_sections.lower()
        for word in blocklist:
            assert word not in lowered, f"{word!r} found in rendered data sections"

    def test_coverage_omitted_entirely_when_not_provided(self):
        """No fabricated coverage section when the caller didn't compute
        one (coverage=None is the default)."""
        from utilities.autopatcher.post_patch_evaluation import render_post_patch_investigation

        rendered = render_post_patch_investigation([])
        assert "Anchor Coverage" not in rendered

    def test_coverage_section_appears_before_changed_and_survives_truncation(self):
        from utilities.autopatcher.post_patch_evaluation import CoverageResult, render_post_patch_investigation

        coverage = CoverageResult(total=8, covered=("a.py:foo",), uncovered=tuple(f"b{i}.py:x" for i in range(7)), unattributed=0)
        rendered = render_post_patch_investigation([], coverage)

        assert "### Anchor Coverage" in rendered
        assert "1 of 8 element(s)" in rendered
        assert "7 are not" in rendered
        coverage_idx = rendered.index("### Anchor Coverage")
        assert coverage_idx < rendered.index("No anchors were available")

        # Placed early enough to survive a tight character budget, unlike
        # a section placed last (which _hard_clamp would drop first). The
        # budget below is tight enough to truncate well before any of the
        # Changed/Disappeared/Unchanged/Remaining-Unknowns sections could
        # render, yet still fits header + preamble + Anchor Coverage.
        tight = render_post_patch_investigation([], coverage, max_chars=760)
        assert "Anchor Coverage" in tight
        assert "*(truncated to fit the character budget)*" in tight

    def test_uncovered_list_capped_with_plus_n_more(self):
        from utilities.autopatcher.post_patch_evaluation import CoverageResult, render_post_patch_investigation

        coverage = CoverageResult(total=7, covered=(), uncovered=tuple(f"f{i}.py:x" for i in range(7)), unattributed=0)
        rendered = render_post_patch_investigation([], coverage)
        assert "(+2 more)" in rendered

    def test_unchanged_caveat_appears_only_when_something_is_uncovered(self):
        from utilities.autopatcher.post_patch_evaluation import (
            CoverageResult, evaluate_anchors, render_post_patch_investigation,
        )

        func_id = "a.py:foo"
        anchors = [_resolved_function_anchor(func_id)]
        context = _context({func_id: _function(func_id)})
        observations = evaluate_anchors(anchors, context)

        fully_covered = CoverageResult(total=1, covered=(func_id,), uncovered=(), unattributed=0)
        rendered_full = render_post_patch_investigation(observations, fully_covered)
        unchanged_full = rendered_full[rendered_full.index("### Unchanged"):rendered_full.index("### Remaining Unknowns")]
        assert "see Anchor Coverage above" not in unchanged_full

        partially_covered = CoverageResult(total=2, covered=(func_id,), uncovered=("b.py:bar",), unattributed=0)
        rendered_partial = render_post_patch_investigation(observations, partially_covered)
        unchanged_partial = rendered_partial[rendered_partial.index("### Unchanged"):rendered_partial.index("### Remaining Unknowns")]
        assert "see Anchor Coverage above" in unchanged_partial

    def test_reproduces_the_cve_2023_43804_report_shape(self):
        """End-to-end render check for the motivating case: a
        constant_value anchor shows the actual fix under Changed, and
        Anchor Coverage names what else in the file has no anchor at
        all -- instead of today's misleading "0 changed, 7 unchanged"."""
        from utilities.autopatcher.post_patch_evaluation import (
            CoverageResult, evaluate_anchors, render_post_patch_investigation,
        )

        anchor = _constant_value_anchor(
            "retry.py", "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT", "Retry",
            "frozenset_call", frozenset({"Authorization"}),
        )
        context = _constant_context(constants={
            "retry.py": {"Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT": _constant_entry(
                "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT", "Retry", "DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
                value=frozenset({"Authorization", "Cookie"}),
            )}
        })
        observations = evaluate_anchors([anchor], context)
        coverage = CoverageResult(total=1, covered=("retry.py:Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT",), uncovered=(), unattributed=0)

        rendered = render_post_patch_investigation(observations, coverage)
        changed_idx = rendered.index("### Changed")
        disappeared_idx = rendered.index("### Disappeared")
        assert "constant_value:retry.py:Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT" in rendered[changed_idx:disappeared_idx]
        assert "frozenset({'Authorization'})" in rendered[changed_idx:disappeared_idx]
        assert "1 of 1 element(s)" in rendered

    def test_patch_touched_changed_item_is_tagged(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors, render_post_patch_investigation

        anchor = _constant_value_anchor(
            "retry.py", "Retry.X", "Retry", "frozenset_call", frozenset({"Authorization"}), origin="patch_touched",
        )
        context = _constant_context(constants={
            "retry.py": {"Retry.X": _constant_entry("Retry.X", "Retry", "X", value=frozenset({"Authorization", "Cookie"}))}
        })
        rendered = render_post_patch_investigation(evaluate_anchors([anchor], context))
        changed_section = rendered[rendered.index("### Changed"):rendered.index("### Disappeared")]
        assert "(discovered from patch diff)" in changed_section

    def test_pre_patch_changed_item_is_not_tagged(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors, render_post_patch_investigation

        anchor = _constant_value_anchor(
            "retry.py", "Retry.X", "Retry", "frozenset_call", frozenset({"Authorization"}), origin="pre_patch",
        )
        context = _constant_context(constants={
            "retry.py": {"Retry.X": _constant_entry("Retry.X", "Retry", "X", value=frozenset({"Authorization", "Cookie"}))}
        })
        rendered = render_post_patch_investigation(evaluate_anchors([anchor], context))
        changed_section = rendered[rendered.index("### Changed"):rendered.index("### Disappeared")]
        assert "(discovered from patch diff)" not in changed_section

    def test_patch_touched_disappeared_item_is_tagged(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors, render_post_patch_investigation

        anchor = _resolved_function_anchor("a.py:foo", origin="patch_touched")
        context = _context({})  # func_id no longer present -> disappeared
        rendered = render_post_patch_investigation(evaluate_anchors([anchor], context))
        disappeared_section = rendered[rendered.index("### Disappeared"):rendered.index("### Unchanged")]
        assert "(discovered from patch diff)" in disappeared_section

    def test_unchanged_summary_has_no_second_origin_breakdown(self):
        """Explicit requirement: Unchanged stays a single breakdown axis
        (by anchor_kind), never a second one by origin."""
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors, render_post_patch_investigation

        func_id = "a.py:foo"
        anchors = [
            _resolved_function_anchor(func_id, origin="pre_patch"),
            _resolved_function_anchor("b.py:bar", origin="patch_touched"),
        ]
        context = _context({func_id: _function(func_id), "b.py:bar": _function("b.py:bar")})
        rendered = render_post_patch_investigation(evaluate_anchors(anchors, context))
        unchanged_section = rendered[rendered.index("### Unchanged"):rendered.index("### Remaining Unknowns")]
        assert "2 anchor(s) confirmed unchanged (resolved_function: 2)" in unchanged_section
        assert "patch_touched" not in unchanged_section
        assert "pre_patch" not in unchanged_section
        assert "discovered from patch diff" not in unchanged_section


# ---------------------------------------------------------------------------
# Release-polish change #2: human-readable Anchor values in Changed
# ---------------------------------------------------------------------------

class TestHumanReadableAnchorValues:
    """The Changed section must render concise, maintainer-readable
    before/after values -- never a raw Python NamedTuple repr (e.g.
    "ResolvedFunctionValue(start_line=1, end_line=5)" or
    "ConstantValueValue(ast_literal_kind=...)"). Presentation only --
    evaluate_anchors()'s own status/comparison logic is untouched."""

    def test_resolved_function_shows_line_range_not_namedtuple_repr(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors, render_post_patch_investigation

        anchor = _resolved_function_anchor("a.py:foo", start_line=1, end_line=5)
        context = _context({"a.py:foo": _function("a.py:foo", start_line=20, end_line=30)})
        rendered = render_post_patch_investigation(evaluate_anchors([anchor], context))
        changed_section = rendered[rendered.index("### Changed"):rendered.index("### Disappeared")]

        assert "ResolvedFunctionValue" not in changed_section
        assert "lines 1-5" in changed_section
        assert "lines 20-30" in changed_section

    def test_reachability_shows_plain_words_not_namedtuple_repr(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors, render_post_patch_investigation

        func_id = "a.py:foo"
        anchor = _reachability_anchor(func_id, reachable=True, entry_point_path=["entry.py:main", func_id])
        context = _context({func_id: _function(func_id)})  # no reverse edges/entry points -> unreachable now
        rendered = render_post_patch_investigation(evaluate_anchors([anchor], context))
        changed_section = rendered[rendered.index("### Changed"):rendered.index("### Disappeared")]

        assert "ReachabilityValue" not in changed_section
        assert "reachable" in changed_section
        assert "not reachable" in changed_section

    def test_constant_value_shows_bare_literal_not_wrapper_repr(self):
        """Regression guard alongside test_reproduces_the_cve_2023_43804_report_shape:
        the wrapper's own class name / ast_literal_kind field must not
        appear -- only the literal's own value."""
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors, render_post_patch_investigation

        anchor = _constant_value_anchor(
            "retry.py", "Retry.X", "Retry", "frozenset_call", frozenset({"Authorization"}),
        )
        context = _constant_context(constants={
            "retry.py": {"Retry.X": _constant_entry("Retry.X", "Retry", "X", value=frozenset({"Authorization", "Cookie"}))}
        })
        rendered = render_post_patch_investigation(evaluate_anchors([anchor], context))
        changed_section = rendered[rendered.index("### Changed"):rendered.index("### Disappeared")]

        assert "ConstantValueValue" not in changed_section
        assert "ast_literal_kind" not in changed_section
        assert "frozenset({'Authorization'})" in changed_section

    def test_unknown_value_shape_falls_back_safely(self):
        """Defensive fallback: a value that doesn't match its kind's
        expected NamedTuple shape must never raise."""
        from utilities.autopatcher.post_patch_evaluation import _format_anchor_value

        assert _format_anchor_value("resolved_function", "unexpected-shape") == "unexpected-shape"
        assert _format_anchor_value("resolved_function", None) == "unknown"


# ---------------------------------------------------------------------------
# Release-polish change #8: Post-Patch Investigation preamble provenance
# ---------------------------------------------------------------------------

class TestPreamblePatchTouchedProvenance:
    def test_preamble_clarifies_patch_touched_provenance(self):
        """The preamble must distinguish this evidence (gathered from the
        final patch diff, after generation) from Repository Context
        (locations selected before the patch existed) -- worded without a
        directional "above"/"below" claim, since this function also renders
        correctly when exercised standalone (as this test does)."""
        from utilities.autopatcher.post_patch_evaluation import render_post_patch_investigation

        rendered = render_post_patch_investigation([])

        assert "after the patch was generated" in rendered
        assert "Repository Context" in rendered
        assert "before the patch existed" in rendered
